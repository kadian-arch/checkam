"""What a message claims, and how the person can check that claim themselves through an official channel.

Every scam in the Stop Arnaque 237 taxonomy rests on a claim the person cannot see behind: money arrived,
the account is blocked, an agent will call, a relative is in hospital, a parcel is held. A claim like that,
from a sender anyone can type, is never cleared on its wording alone: the answer gives the one check that
settles it and, when the message is too thin to judge, the question that would settle it."""
import re

# name: (pattern, check en, check fr, question en, question fr)
CLAIMS = {
    # the most specific claims come first: the first one found decides the check the person is given
    "code_by_mistake": (
        r"\b(code|otp)\b[^.\n]{0,60}\b(by mistake|par erreur|forward|transf[ée]r|renvo|send (?:it|me|the)|envoie[sz]?[- ]moi|lis[- ]moi|read (?:it|me))"
        r"|\b(forward|transf[ée]r\w*|renvo\w*|send)\b[^.\n]{0,30}\b(the code|le code|ce code|that code)\b",
        "A code you receive by SMS is the key to your own account (WhatsApp, MoMo, your bank). Never forward it or read it out to anyone, even a friend: whoever asks is trying to take over your account",
        "Un code reçu par SMS est la clé de votre propre compte (WhatsApp, MoMo, votre banque). Ne le transférez et ne le lisez jamais à personne, même à un ami : celui qui le demande veut prendre votre compte",
        "Did someone ask you to forward or read out a code you received?",
        "Quelqu'un vous a-t-il demandé de transférer ou de lire un code que vous avez reçu ?"),
    "sent_by_mistake": (
        r"\b(by mistake|mistakenly|wrongly sent|sent (?:it )?(?:to you )?wrong|wrong number|par erreur|erron[ée]ment|je me suis tromp[ée]|trompé de num)",
        "Dial your operator's balance code yourself (*126# for MTN, #150# for Orange). If the money is not there, it never came. If it is, a real mistake is reversed by the operator: never send it back yourself",
        "Composez vous-même le code de solde de votre opérateur (*126# pour MTN, #150# pour Orange). Si l'argent n'y est pas, il n'est jamais arrivé. S'il y est, une vraie erreur est annulée par l'opérateur : ne le renvoyez jamais vous-même",
        "Is the money really in your balance when you dial the code yourself?",
        "L'argent est-il vraiment dans votre solde quand vous composez le code vous-même ?"),
    "security_alert": (
        r"\b(tentative de connexion|connexion (?:inhabituelle|suspecte|non autoris[ée]e)|login attempt|sign-?in attempt|unusual (?:activity|login|sign-?in)|unauthori[sz]ed (?:login|access|transaction)|"
        r"activit[ée] suspecte|suspicious activity|security alert|alerte de s[ée]curit[ée]|votre compte a [ée]t[ée] (?:pirat|compromis)|account (?:has been )?compromised)",
        "Open the official app yourself, or dial your operator's code, to see your account. A real security alert never asks you to click a link or give a code",
        "Ouvrez vous-même l'application officielle, ou composez le code de votre opérateur, pour voir votre compte. Une vraie alerte de sécurité ne demande jamais de cliquer un lien ni de donner un code",
        "Does it ask you to click a link, log in or give a code to cancel or secure something?",
        "Vous demande-t-il de cliquer un lien, de vous connecter ou de donner un code pour annuler ou sécuriser quelque chose ?"),
    "money_received": (
        r"\b(you have (?:just )?received|vous avez re[çc]u|vous venez de recevoir|received [\d .,]+ ?(?:xaf|fcfa|f)\b|cr[ée]dit[ée] sur votre compte|credited to your account)",
        "Dial your operator's balance code yourself (*126# for MTN, #150# for Orange): if the money is not in your balance, it never came",
        "Composez vous-même le code de solde de votre opérateur (*126# pour MTN, #150# pour Orange) : si l'argent n'est pas dans votre solde, il n'est jamais arrivé",
        "Is the money really in your balance when you dial the code yourself?",
        "L'argent est-il vraiment dans votre solde quand vous composez le code vous-même ?"),
    "account_blocked": (
        r"\b(compte|account|sim|ligne|line|num[ée]ro|wallet|portefeuille)\W+(?:\w+\W+){0,4}(bloqu|suspend|d[ée]sactiv|deactivat|ferm[ée]|closed|restrict|gel[ée]|frozen)",
        "Dial your operator's code yourself or go to an operator shop: an account is never unblocked by calling a number in a message",
        "Composez vous-même le code de votre opérateur ou allez dans une agence : un compte ne se débloque jamais en appelant un numéro reçu par message",
        "Does it ask you to call a number, give a code or pay something to unblock it?",
        "Vous demande-t-on d'appeler un numéro, de donner un code ou de payer pour le débloquer ?"),
    "agent_calling": (
        r"\b(agent|service client|customer (?:care|service)|conseiller|support|technicien)\b[^.\n]{0,60}\b(va vous appeler|will call|vous appellera|vous contactera|will contact|calling you|vous appelle)",
        "Hang up and call your operator yourself on its official number: a real agent never asks for your PIN or a code",
        "Raccrochez et appelez vous-même votre opérateur sur son numéro officiel : un vrai agent ne demande jamais votre code secret",
        "Did the caller ask for your PIN, a code you received, or to dial something?",
        "La personne vous a-t-elle demandé votre code secret, un code reçu ou de composer quelque chose ?"),
    "prize": (
        r"\b((?:vous avez|you have|tu as|you've)\W+(?:\w+\W+){0,2}(?:gagn|won)|f[ée]licitations[^.\n]{0,80}(?:gagn|won|s[ée]lectionn|selected|winner|gagnant)|"
        r"congratulations[^.\n]{0,80}(?:won|selected|winner)|tirage au sort|lucky draw|you are (?:the|our) winner)",
        "Check the promotion on the operator's or brand's official page yourself: a real prize never asks you to pay or give a code",
        "Vérifiez la promotion vous-même sur la page officielle de l'opérateur ou de la marque : un vrai gain ne demande jamais de payer ni de donner un code",
        "To receive the prize, does it ask you to pay, give a code or open a link?",
        "Pour recevoir le gain, vous demande-t-on de payer, de donner un code ou d'ouvrir un lien ?"),
    "relative_trouble": (
        r"\b(accident|h[ôo]pital|hospital|urgence|emergency|arr[êe]t[ée]e?|arrested|gard[ée] [àa] vue|bloqu[ée]e? [àa] la fronti|stuck at the border|kidnapp|enlev[ée])",
        "Call your relative on the number you already know, or someone who is with them, before you send anything",
        "Appelez votre proche sur le numéro que vous connaissez déjà, ou quelqu'un qui est avec lui, avant d'envoyer quoi que ce soit",
        "Have you reached the person on the number you already know?",
        "Avez-vous joint la personne sur le numéro que vous connaissez déjà ?"),
    "new_number": (
        r"\b(nouveau num[ée]ro|new number|mon num[ée]ro a chang|changed my number|this is my new|c'est mon nouveau|j'ai chang[ée] de num)",
        "Call the old number you know, or ask a question only the real person can answer",
        "Appelez l'ancien numéro que vous connaissez, ou posez une question que seule la vraie personne peut connaître",
        "Have you spoken to the person on their old number?",
        "Avez-vous parlé à la personne sur son ancien numéro ?"),
    "withdrawal_approval": (
        r"\b(confirm|valid|approuv|approve|accept|autoris)\w*\W+(?:\w+\W+){0,5}(retrait|withdrawal|cash ?out|paiement|payment request|demande de paiement)",
        "Never approve a withdrawal or payment you did not start yourself: approving it takes money out of your account",
        "N'approuvez jamais un retrait ou un paiement que vous n'avez pas lancé vous-même : l'approuver fait sortir l'argent de votre compte",
        "Did you start this withdrawal or payment yourself?",
        "Avez-vous lancé ce retrait ou ce paiement vous-même ?"),
    "official_demand": (
        r"\b(police|gendarmerie|douane|customs|imp[ôo]ts|tax office|minist[eè]re|ministry|tribunal|court|dgsn|minfi|mintp|minesec|minesup)\b[^.\n]{0,100}\b(pay|payez|amende|fine|frais|fee|r[ée]gularis|settle)",
        "Go to the office in person or use its official website: public bodies never take payments to a personal mobile money number",
        "Allez au bureau en personne ou utilisez son site officiel : les services publics ne se font jamais payer sur un numéro mobile money personnel",
        "Which number or account does it ask you to pay?",
        "Sur quel numéro ou quel compte vous demande-t-on de payer ?"),
    "threat": (
        r"\b(menace|on va te tuer|we will kill|vid[ée]os? intimes?|photos? intimes?|nudes?|publier (?:vos|tes) (?:photos|vid)|leak your|expose you|ransom|ran[çc]on|kidnap)",
        "Do not pay and do not reply. Keep the messages and report them to the police (117)",
        "Ne payez pas et ne répondez pas. Gardez les messages et signalez-les à la police (117)",
        "Do you know who is sending these threats?",
        "Savez-vous qui envoie ces menaces ?"),
    "sim_change": (
        r"\b(changement de (?:sim|puce|carte sim)|sim swap|nouvelle (?:sim|puce)|replace your sim|swap your sim|mise [àa] jour de (?:votre )?sim|sim update)",
        "Change or replace a SIM only in an operator shop, with your ID. Never give the code you receive by SMS",
        "Changez ou remplacez une SIM seulement en agence, avec votre pièce d'identité. Ne donnez jamais le code reçu par SMS",
        "Has someone asked you for a code you received by SMS?",
        "Quelqu'un vous a-t-il demandé un code reçu par SMS ?"),
    "romance_money": (
        r"\b(my love|mon amour|darling|ch[ée]rie?|baby|bae|honey)\b[^.\n]{0,100}\b(send|envoie|transfer|money|argent|frais|fee|ticket|billet)",
        "Do not send money to someone you have never met in person, whatever the story",
        "N'envoyez pas d'argent à quelqu'un que vous n'avez jamais rencontré en personne, quelle que soit l'histoire",
        "Have you ever met this person face to face?",
        "Avez-vous déjà rencontré cette personne en vrai ?"),
    "parcel_held": (
        r"\b(colis|parcel|package|paquet|livraison|delivery)\b[^.\n]{0,100}\b(bloqu|held|retenu|douane|customs|frais|fee|payer|pay)",
        "Track the parcel on the carrier's official site with the number from your own order. Pay only on delivery, after you see the item",
        "Suivez le colis sur le site officiel du transporteur avec le numéro de votre propre commande. Payez seulement à la livraison, après avoir vu l'article",
        "Did you order something that is on its way?",
        "Avez-vous commandé quelque chose qui est en route ?"),
    "loan_fee": (
        r"\b(pr[êe]t|loan|cr[ée]dit|financement)\b[^.\n]{0,100}\b(frais|fee|assurance|insurance|dossier|caution|deposit|avance)",
        "Real lenders take their fees from the loan itself, never before. Borrow only through your bank, a microfinance or the official operator app",
        "Les vrais prêteurs prennent leurs frais sur le prêt, jamais avant. Empruntez seulement auprès de votre banque, d'une microfinance ou de l'application officielle de l'opérateur",
        "Do they ask you to pay something before you receive the loan?",
        "Vous demande-t-on de payer quelque chose avant de recevoir le prêt ?"),
    "official_document": (
        r"\b(communiqu[ée] (?:officiel|de presse|du minist)|note de service|arr[êe]t[ée] (?:minist[ée]riel|n°)|d[ée]cision n°|official (?:notice|communiqu)|press release)",
        "Check it on the ministry's or institution's official website or page: forged communiqués circulate on WhatsApp",
        "Vérifiez-le sur le site ou la page officielle du ministère ou de l'institution : de faux communiqués circulent sur WhatsApp",
        "Where did you see this communiqué first?",
        "Où avez-vous vu ce communiqué en premier ?"),
    "opportunity": (
        r"\b(recrut|recruit|hiring|embauche|offre d'emploi|job offer|concours|admission|bourse|scholarship|visa|volontaires?|volunteer|candidature|postulez|apply now|"
        r"rejoign\w* (?:notre|nos|l'|la|le)|join our|type de contrat|temps plein|full[- ]time|former \d+ jeunes|stage r[ée]mun[ée]r|internship)",
        "Find the offer yourself on the employer's, school's or ministry's official website: real ones never ask for a fee",
        "Retrouvez l'offre vous-même sur le site officiel de l'employeur, de l'école ou du ministère : les vraies ne demandent jamais de frais",
        "Do they ask for a fee, your ID or your diplomas to apply?",
        "Vous demande-t-on des frais, votre pièce d'identité ou vos diplômes pour postuler ?"),
}

_COMPILED = {k: re.compile("(?i)" + v[0]) for k, v in CLAIMS.items()}


# "do not forward this code", "votre compte n'est pas bloqué": a denied claim is advice, not a claim
_DENIED = re.compile(r"(?i)\b(do not|don'?t|never|not|jamais|ne|pas)\b|\bn['’]")


def found(text: str) -> list[str]:
    """Every claim the message makes, in the order of the table."""
    text = text or ""
    return [k for k, rx in _COMPILED.items()
            if any(not _DENIED.search(text[max(0, m.start() - 25):m.end()]) for m in rx.finditer(text))]


def check(name: str, lang: str) -> str:
    return CLAIMS[name][2 if lang == "fr" else 1]


def question(name: str, lang: str) -> str:
    return CLAIMS[name][4 if lang == "fr" else 3]


# when nothing in the message points anywhere, these settle most cases
GENERAL = {
    "sender": ("Who sent it? The name or number shown at the top of the message", "Qui l'a envoyé ? Le nom ou le numéro affiché en haut du message"),
    "ask": ("What does it ask you to do: send money, give a code, call a number or open a link?",
            "Que vous demande-t-il : envoyer de l'argent, donner un code, appeler un numéro ou ouvrir un lien ?"),
    "rest": ("Is there more to the message? Paste all of it, or send a screenshot", "Le message est-il plus long ? Collez-le en entier, ou envoyez une capture"),
}


def questions(facts: dict, lang: str, limit: int = 3) -> list[str]:
    """The few questions that would let the agents decide, most useful first."""
    i = 1 if lang == "fr" else 0
    # "who sent it?" is asked on its own (the answer is the sender, not more text), so it is not in this list
    out = [question(c, lang) for c in found(facts.get("text", ""))]
    if not facts.get("asks"):
        out.append(GENERAL["ask"][i])
    if len((facts.get("text") or "").split()) < 25:
        out.append(GENERAL["rest"][i])
    seen, uniq = set(), []
    for q in out:
        if q not in seen:
            seen.add(q)
            uniq.append(q)
    return uniq[:limit]
