"""Learn how much each agent's evidence should weigh, from the labelled messages, instead of hand-set weights.

Stacking: every evaluated message becomes a row of signals (what each tool found and in which direction,
plus the message facts the verdict reads), and a logistic regression (scikit-learn) learns the weights.
Measured with nested cross-validation: an outer stratified 10-fold split scores every message with a model
that never saw it; inside each training part, a grid search picks the regularisation and an inner
cross-validation picks the threshold. The weights are then exported to JSON, so the live server applies
them with one dot product and needs no ML library.

  pip install -r api/requirements-dev.txt
  python api/scripts/learn_weights.py evals/results-v4-all-all.json            # report only
  python api/scripts/learn_weights.py evals/results-v4-all-all.json --save     # also write the weights
"""
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_predict

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "api"))
from checkam.learned import NAMES, features  # noqa: E402  (the same row the live server builds)

OUT = ROOT / "api" / "checkam" / "data" / "learned_weights.json"
GRID = {"C": [0.03, 0.1, 0.3, 1.0, 3.0]}


def model() -> GridSearchCV:
    return GridSearchCV(LogisticRegression(class_weight="balanced", max_iter=5000), GRID, scoring="f1",
                        cv=StratifiedKFold(5, shuffle=True, random_state=11))


def threshold(probs: np.ndarray, y: np.ndarray) -> float:
    """Highest F1; on a tie the higher threshold, so fewer false alarms."""
    best, t_best = -1.0, 0.5
    for t in np.arange(0.2, 0.91, 0.01):
        flag = probs >= t
        tp, fp, fn = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum()), int((~flag & (y == 1)).sum())
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 >= best:
            best, t_best = f1, float(round(t, 2))
    return t_best


def metrics(flag, y) -> dict:
    flag, y = np.asarray(flag, bool), np.asarray(y, int)
    tp, fp, fn = int((flag & (y == 1)).sum()), int((flag & (y == 0)).sum()), int((~flag & (y == 1)).sum())
    return {"precision": round(tp / (tp + fp), 3) if tp + fp else 0.0, "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
            "false_alarms": f"{fp} of {int((y == 0).sum())}", "missed": fn}


def main():
    rows = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["results"]
    rows = [r for r in rows if r.get("verdict") != "error" and r.get("profile") is not None]
    X = np.array([features(r.get("signals", []), r["profile"]) for r in rows])
    y = np.array([1 if r["label"] == "scam" else 0 for r in rows])
    rule = np.array([r["verdict"] in ("scam", "suspicious") for r in rows])
    unsure = np.array([r["verdict"] == "cant_tell" for r in rows])

    learned = np.zeros(len(rows), bool)
    for train, test in StratifiedKFold(10, shuffle=True, random_state=7).split(X, y):
        # threshold from an inner cross-validation on the training part only
        inner = cross_val_predict(model(), X[train], y[train], cv=StratifiedKFold(5, shuffle=True, random_state=13), method="predict_proba")[:, 1]
        t = threshold(inner, y[train])
        m = model().fit(X[train], y[train])
        learned[test] = m.predict_proba(X[test])[:, 1] >= t

    report = {"messages": len(rows), "scams": int(y.sum()),
              "rules (hand-set weights)": metrics(rule, y),
              "learned weights (nested 10-fold cross-validation)": metrics(learned, y),
              "learned OR rules": metrics(learned | rule, y),
              "learned AND rules": metrics(learned & rule, y),
              # how it runs live: the rules decide; the weights only settle what the rules left at "need more details"
              "rules, learned settles only the unsure (live)": metrics(rule | (unsure & learned), y),
              "unsure left after that": int((unsure & ~learned).sum())}
    print(json.dumps(report, indent=2))
    if "--save" in sys.argv:
        m = model().fit(X, y)
        best = m.best_estimator_
        t = threshold(cross_val_predict(model(), X, y, cv=StratifiedKFold(5, shuffle=True, random_state=13), method="predict_proba")[:, 1], y)
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_text(json.dumps({"names": NAMES, "weights": [round(float(v), 5) for v in best.coef_[0]], "bias": round(float(best.intercept_[0]), 5),
                                   "threshold": t, "C": best.C, "trained_on": len(rows), "cross_validated": report}, indent=2), encoding="utf-8")
        top = sorted(zip(NAMES, best.coef_[0]), key=lambda x: -abs(x[1]))[:12]
        print("saved", OUT)
        print("strongest signals:", [(n, round(float(v), 2)) for n, v in top])


if __name__ == "__main__":
    main()
