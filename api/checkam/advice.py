"""What to do next, written for the scheme in front of the person. Only official channels are ever named;
every line has to fit this message, so a visa lottery never gets PIN advice and a receipt never gets job advice."""
import re

# the operator lines are fixed: the model never invents a number to call
OPERATOR = {
    "mtn": {"en": "MTN MoMo: dial *126# yourself to see your real balance, or WhatsApp MTN on 650 52 87 87",
            "fr": "MTN MoMo : composez vous-même *126# pour voir votre vrai solde, ou écrivez à MTN sur WhatsApp au 650 52 87 87"},
    "orange": {"en": "Orange Money: dial #150# yourself to see your real balance, or WhatsApp Orange's anti-scam line on 698 71 71 71",
               "fr": "Orange Money : composez vous-même #150# pour voir votre vrai solde, ou écrivez à la ligne anti-arnaque d'Orange sur WhatsApp au 698 71 71 71"},
}

SCHEMES = {
    # name: (pattern over text + scam types + the model's scheme name, label en, label fr)
    "visa_scholarship": (r"visa|lottery|loterie|scholarship|bourse|immigra|study abroad|[ée]tudier [àa] l'[ée]tranger|work permit|permis de travail|green card|dv ?lottery|fake_scholarship_visa",
                         "a fake visa or scholarship offer", "une fausse offre de visa ou de bourse"),
    "job": (r"recrut|recruit|job|emploi|hiring|embauche|stage|internship|salaire|salary|fake_job|concours|admission|candidat|volontaire|volunteer|rejoign\w* (?:notre|nos|l'|la|le)|join our|type de contrat|temps plein|full[- ]time|former \d+ jeunes",
            "a fake job or exam offer", "une fausse offre d'emploi ou de concours"),
    "investment": (r"invest|ponzi|crypto|bitcoin|forex|trading|minage|mining|machine|doubl|retrait|withdraw|solde retirable|invitation[_ ]code|parrain|referral|rendement|profit",
                   "a fake investment", "un faux investissement"),
    "loan": (r"loan|pr[êe]t|cr[ée]dit rapide|borrow|emprunt|loan_scam", "a fake loan", "un faux prêt"),
    "reversal": (r"par erreur|by mistake|mistaken|wrong number|wrong_number_reversal|renvoy|send (?:it )?back|rembours|refund|accidental (?:transfer|deposit|payment)|"
                 r"fake (?:credit|receipt|deposit)|faux re[çc]u|vous avez re[çc]u [\d .,]+ ?(?:xaf|fcfa|f) de|you have received [\d .,]+ ?(?:xaf|fcfa|f) from",
                 "money 'sent by mistake'", "l'argent « envoyé par erreur »"),
    "credential": (r"\bpin\b|code secret|otp|mot de passe|password|credential_request|account_blocked|bloqu|suspend|fake_agent|agent|service client|customer care|sim_swap|"
                   r"\d[- ]digit code|code (?:[àa] \d chiffres|de v[ée]rification)|verification code|forward (?:it|the code|me the code)|transf[ée]re[rz]?[- ]le",
                   "someone after your PIN or account", "quelqu'un qui veut votre code ou votre compte"),
    "prize": (r"gagn|won|winner|prize|lot |cadeau|gift|promo|f[ée]licitations|congratulations|anniversaire|tirage|fake_prize_promo",
              "a fake prize", "un faux gain"),
    "seller": (r"livraison|delivery|colis|parcel|douane|customs|seller|vendeur|commande|order|fake_seller_delivery", "a fake seller or delivery", "un faux vendeur ou une fausse livraison"),
    "family": (r"maman|papa|tonton|tata|my dear|ma ch[ée]rie|mon fr[èe]re|ma s[œo]e?ur|hospital|h[ôo]pital|accident(?!al)s?|urgence|emergency|stuck|bloqu[ée]e? [àa]|border|fronti[èe]re|"
               r"phone is (?:almost )?(?:off|dead)|batterie|family_emergency|hacked_account_money", "a fake emergency from someone you know",
               "une fausse urgence d'un proche"),
}

LINES = {
    "visa_scholarship": {
        "do": ("Check on the official site of that government or school yourself (Canada: canada.ca, USA: state.gov, France: campusfrance.org). Real programmes never recruit through WhatsApp or Telegram links",
               "Vérifiez vous-même sur le site officiel du gouvernement ou de l'école (Canada : canada.ca, USA : state.gov, France : campusfrance.org). Les vrais programmes ne recrutent jamais par lien WhatsApp ou Telegram"),
        "dont": [("Do not pay any application, processing or 'reservation' fee", "Ne payez aucun frais de dossier, de traitement ou de « réservation »"),
                 ("Do not send your passport, ID card or diplomas", "N'envoyez ni passeport, ni carte d'identité, ni diplômes")]},
    "job": {
        "do": ("Look up the company yourself, on its official website or at its office, before you reply",
               "Renseignez-vous vous-même sur l'entreprise, sur son site officiel ou à son bureau, avant de répondre"),
        "dont": [("Never pay to get a job, a training, a medical test or a uniform", "Ne payez jamais pour obtenir un emploi, une formation, une visite médicale ou une tenue"),
                 ("Do not send your ID card or diplomas to an unknown contact", "N'envoyez pas votre carte d'identité ni vos diplômes à un inconnu")]},
    "investment": {
        "do": ("Real investments never promise a fixed big return. Talk to someone you trust before you put in any money",
               "Un vrai investissement ne promet jamais un gros gain fixe. Parlez-en à une personne de confiance avant de mettre de l'argent"),
        "dont": [("Do not deposit more money to 'unlock' a withdrawal", "Ne déposez pas d'argent pour « débloquer » un retrait"),
                 ("Do not share your invitation code: that pulls your friends into the scam", "Ne partagez pas votre code d'invitation : cela entraîne vos amis dans l'arnaque")]},
    "loan": {
        "do": ("Borrow only through your bank, your microfinance or the official operator app", "Empruntez seulement auprès de votre banque, de votre microfinance ou de l'application officielle de l'opérateur"),
        "dont": [("Never pay a fee before you receive a loan", "Ne payez jamais de frais avant de recevoir un prêt")]},
    "reversal": {
        "do": None,  # the operator line says it: check the real balance yourself
        "dont": [("Do not send back money 'sent by mistake'. If it was real, the operator reverses it", "Ne renvoyez pas l'argent « envoyé par erreur ». Si c'était vrai, l'opérateur l'annule lui-même")]},
    "credential": {
        "do": None,
        "dont": [("Never give your PIN or a code you received by SMS, not even to someone who says they work for MTN or Orange",
                  "Ne donnez jamais votre code secret ni un code reçu par SMS, même à quelqu'un qui dit travailler pour MTN ou Orange"),
                 ("Do not dial a code that someone sends you", "Ne composez pas un code que quelqu'un vous envoie")]},
    "prize": {
        "do": ("Real promotions are on the operator's official page and never ask you to pay to receive a prize",
               "Les vraies promotions sont sur la page officielle de l'opérateur et ne demandent jamais de payer pour recevoir un gain"),
        "dont": [("Do not pay any fee to receive a prize", "Ne payez aucun frais pour recevoir un gain")]},
    "seller": {
        "do": ("Pay only on delivery, after you have seen the item", "Payez seulement à la livraison, après avoir vu l'article"),
        "dont": [("Do not pay delivery or customs fees in advance", "Ne payez pas de frais de livraison ou de douane à l'avance")]},
    "family": {
        "do": ("Call your relative on the number you already know before you do anything", "Appelez votre proche sur le numéro que vous connaissez déjà avant de faire quoi que ce soit"),
        "dont": [("Do not send money before you have spoken to them yourself", "N'envoyez pas d'argent avant de lui avoir parlé vous-même")]},
}

ASK_LINES = {
    "click_link": ("Do not open the link, and never type a code or password on that site", "N'ouvrez pas le lien, et ne tapez jamais de code ou de mot de passe sur ce site"),
    "call_back": ("Do not call or reply to the number in the message", "N'appelez pas et ne répondez pas au numéro du message"),
    "pin": ("Never give your PIN or a code you received by SMS", "Ne donnez jamais votre code secret ni un code reçu par SMS"),
    "personal_info": ("Do not send your ID card, passport or photos", "N'envoyez ni carte d'identité, ni passeport, ni photos"),
    "send_money": ("Do not send any money", "N'envoyez pas d'argent"),
}
WARN_OTHERS = ("Warn the people who may have received it too", "Prévenez les personnes qui ont pu le recevoir aussi")
NOT_YET = ("Do not act on it yet. Check with the official source first, using a number or site you find yourself",
           "N'agissez pas encore. Vérifiez d'abord auprès de la source officielle, avec un numéro ou un site que vous trouvez vous-même")


def scheme_of(text: str, scam_types: list[str], model_scheme: str = "") -> str | None:
    """What this message itself says weighs most; the analyst's reading next; the types of similar old
    reports only break ties, since a neighbour can be a different scheme."""
    best, top = None, 0
    for name, (rx, _, _) in SCHEMES.items():
        rx = rf"(?<![^\W_])(?:{rx})"  # words start where a word starts; stems like "recrut" still take any ending
        direct = 2 * len(re.findall(rx, text, flags=re.I)) + 2 * len(re.findall(rx, model_scheme or "", flags=re.I))
        if not direct:
            continue  # neighbours can break a tie, never name a scheme the message itself does not show
        n = direct + len(re.findall(rx, " ".join(scam_types or []), flags=re.I))
        if n > top:
            best, top = name, n
    return best


def label(scheme: str | None, lang: str) -> str:
    if not scheme:
        return ""
    return SCHEMES[scheme][2 if lang == "fr" else 1]


def steps(verdict: str, scheme: str | None, facts: dict, lang: str, route: str = "", claimed: tuple | None = None) -> tuple[list[str], list[str]]:
    """do_now and dont for the card: at most three of each, every one relevant to this message."""
    i = 1 if lang == "fr" else 0
    brand = next((b for b in facts.get("brands", []) if b in OPERATOR), None)
    asks = set(facts.get("asks", []))
    do, dont = [], []
    if verdict == "looks_genuine":
        if route:
            do.append((f"You can use it through the official route it gives ({route}), typed by you", f"Vous pouvez l'utiliser par la voie officielle indiquée ({route}), en la tapant vous-même")[i])
        do.append(("If anyone later asks for your PIN or a code about it, stop: that part would be a scam",
                   "Si quelqu'un vous demande ensuite votre code secret ou un code à ce sujet, arrêtez : ce serait une arnaque")[i])
        return do, dont
    if verdict == "cant_tell":
        do.append(NOT_YET[i])
        if brand:
            do.append(OPERATOR[brand][lang if lang in ("en", "fr") else "en"])
        for a in ("click_link", "call_back", "pin", "send_money"):
            if a in asks or (a == "click_link" and facts.get("links")):
                dont.append(ASK_LINES[a][i])
        return do[:3], dont[:3]
    plan = LINES.get(scheme or "", {})
    if claimed and scheme in ("visa_scholarship", "job"):
        # the institution the message names, and the only site that can speak for it
        do.append((f"Check on the official site of {claimed[0]} yourself ({claimed[1][0]}). Real programmes never recruit through WhatsApp or Telegram links, and never ask for fees by mobile money",
                   f"Vérifiez vous-même sur le site officiel de {claimed[0]} ({claimed[1][0]}). Les vrais programmes ne recrutent jamais par lien WhatsApp ou Telegram, et ne demandent jamais de frais par mobile money")[i])
    elif plan.get("do"):
        do.append(plan["do"][i])
    money_scheme = scheme in ("reversal", "credential", None) or brand is not None
    if brand and money_scheme:
        do.append(OPERATOR[brand][lang if lang in ("en", "fr") else "en"])
    do.append(WARN_OTHERS[i])
    dont += [d[i] for d in plan.get("dont", [])]
    for a in ("pin", "click_link", "call_back", "personal_info", "send_money"):
        line = ASK_LINES[a][i]
        wanted = a in asks or (a == "click_link" and facts.get("links"))
        if wanted and line not in dont and not (a == "send_money" and dont):
            dont.append(line)
    if not dont:
        dont.append(ASK_LINES["send_money"][i])
    return do[:3], dont[:3]
