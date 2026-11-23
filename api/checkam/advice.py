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
    "visa_scholarship": (r"visa|diversity (?:visa )?lottery|green card lottery|loterie (?:du |de la )?(?:visa|green card)|scholarship|bourse|immigra|study abroad|[ée]tudier [àa] l'[ée]tranger|work permit|permis de travail|green card|dv ?lottery|fake_scholarship_visa",
                         "a fake visa or scholarship offer", "une fausse offre de visa ou de bourse"),
    "job": (r"recrut|recruit|job|emploi|hiring|embauche|stage|internship|salaire|salary|fake_job|candidat|volontaire|volunteer|rejoign\w* (?:notre|nos|l'|la|le)|join our|type de contrat|temps plein|full[- ]time|former \d+ jeunes|vacanc|postule[rz]|"
            r"terms of reference|termes de r[ée]f[ée]rence|apply (?:before|through)|is looking for an?\b",
            "a fake job offer", "une fausse offre d'emploi"),
    "exam": (r"concours|admission|[ée]preuves|leaked (?:exam|paper|question)|exam (?:results?|papers?|questions?)|fuite d(?:es|'[ée]preuves)|fake_concours_admission|enam\b|emia\b",
             "a fake concours or admission offer", "une fausse offre de concours ou d'admission"),
    "investment": (r"invest|ponzi|crypto|bitcoin|forex|trading|minage|mining|machine|doubl(?:e|er|ez|ons)? (?:votre|vos|your|ton|ta|tes|l'argent|money|mise|capital)|doublez|retrait|withdraw(?!al_trap)|solde retirable|invitation[_ ]code|parrain|referral|rendement|profit",
                   "a fake investment", "un faux investissement"),
    "loan": (r"loan|pr[êe]t|cr[ée]dit rapide|borrow|emprunt|loan_scam", "a fake loan", "un faux prêt"),
    "reversal": (r"par erreur|by mistake|mistaken|wrong number|wrong_number_reversal|deposit_withdrawal_trap|renvoy|send (?:it )?back|rembours|refund|accidental (?:transfer|deposit|payment)|"
                 r"fake (?:credit|receipt|deposit)|faux re[çc]u|vous avez re[çc]u [\d .,]+ ?(?:xaf|fcfa|f) de|you have received [\d .,]+ ?(?:xaf|fcfa|f) from",
                 "money 'sent by mistake'", "l'argent « envoyé par erreur »"),
    "credential": (r"\bpin\b|code secret|otp|mot de passe|password|credential_request|account_blocked|bloqu|suspend|fake_agent|agent|service client|customer care|sim_swap|"
                   r"\d[- ]digit code|code (?:[àa] \d chiffres|de v[ée]rification)|verification code|forward (?:it|the code|me the code)|transf[ée]re[rz]?[- ]le",
                   "someone after your PIN or account", "quelqu'un qui veut votre code ou votre compte"),
    "prize": (r"gagn|won|winner|prize|lottery|loterie|tombola|raffle|jackpot|lot |cadeau|gift|promo|f[ée]licitations|congratulations|anniversaire|tirage|fake_prize_promo",
              "a fake prize", "un faux gain"),
    "seller": (r"livraison|delivery|colis|parcel|douane|customs|seller|vendeur|commande|order|fake_seller_delivery", "a fake seller or delivery", "un faux vendeur ou une fausse livraison"),
    "family": (r"maman|papa|tonton|tata|ma ch[ée]rie|mon fr[èe]re|ma s[œo]e?ur|hospital|h[ôo]pital|accident(?!al)s?|urgence|emergency|stuck|bloqu[ée]e? [àa]|border|fronti[èe]re|"
               r"phone is (?:almost )?(?:off|dead)|batterie|family_emergency|hacked_account_money", "a fake emergency from someone you know",
               "une fausse urgence d'un proche"),
    "romance": (r"romance|my love|mon amour|darling|sweetheart|i love you|je t'aime|soulmate|[âa]me s[œo]e?ur|marry|[ée]pouser|dating|site de rencontres?|fianc[ée]",
                "a romance scam", "une arnaque sentimentale"),
    "extortion": (r"threat_extortion|blackmail|chantage|sextortion|nudes?\b|intimate (?:photo|video|image)|(?:photo|vid[ée]o|image)s? intimes?|"
                  r"we will (?:kill|kidnap|publish|expose|leak)|nous allons (?:tuer|publier|enlever|diffuser)|kidnap|enl[èe]vement|ran[çc]on|ransom|expose you|vous exposer",
                  "blackmail or a threat", "un chantage ou une menace"),
    "official": (r"official_impersonation|police|gendarme|imp[ôo]ts|tax office|tribunal|convocation|amende|commissariat|magistrat|procureur|customs officer|agent des douanes",
                 "someone posing as an official", "quelqu'un qui se fait passer pour une autorité"),
    "advance_fee": (r"advance_fee|frais de (?:dossier|d[ée]blocage|traitement|transfert)|(?:processing|unlock(?:ing)?|clearance|release) fees?|d[ée]bloquer (?:les|vos|le|votre) (?:fonds|argent|gain)|"
                    r"release (?:the|your) (?:funds|money)|inheritance|h[ée]ritage|subvention|funding approved|financement accord[ée]",
                    "a fee demanded before a payout", "des frais exigés avant un versement"),
    "phishing": (r"phishing_link|log ?in\b|sign in|connectez-vous|verify your (?:account|identity)|v[ée]rifie[rz] votre (?:compte|identit[ée])|confirm your (?:account|identity)|"
                 r"confirme[rz] votre (?:compte|identit[ée])|update your (?:account|details)|mettre? [àa] jour votre compte",
                 "a link made to steal your login", "un lien fait pour voler vos identifiants"),
    "rental": (r"loyer|\brent\b|caution\b|house for rent|maison [àa] louer|chambre [àa] louer|appartement|\bstudio\b|landlord|bailleur|propri[ée]taire|deposit for (?:the )?(?:house|apartment|room|flat)",
               "a fake rental or housing deposit", "un faux loyer ou une fausse caution"),
    "charity": (r"donat|\bdons?\b|orphelin|orphan|charity|church building|aide humanitaire|cagnotte|fundrais|sick child|enfant malade|help (?:us )?(?:build|rebuild)|aidez[- ]nous",
                "a fake charity appeal", "un faux appel aux dons"),
    "fake_page": (r"fake_social_profile|fake_document|fake (?:page|profile|account|communiqu[ée]|memo)|faux (?:profil|compte|communiqu[ée])|fausse page",
                  "a fake page or document using a known name", "une fausse page ou un faux document au nom d'une personne ou d'une marque connue"),
}
# announcements people apply to: the named institution's own site is the place to check
ANNOUNCEMENTS = ("job", "exam", "visa_scholarship")

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
    "exam": {
        "do": ("Results and admission lists come only from the ministry or the school itself: its communiqué, its notice board or its official site. Check there yourself",
               "Les résultats et les listes d'admission viennent seulement du ministère ou de l'école : son communiqué, son tableau d'affichage ou son site officiel. Vérifiez-y vous-même"),
        "dont": [("Never pay anyone to 'push your file', buy a place or get exam papers", "Ne payez jamais quelqu'un pour « pousser votre dossier », acheter une place ou obtenir des épreuves"),
                 ("Do not send your documents or registration number to an unknown contact", "N'envoyez pas vos documents ni votre numéro de dossier à un inconnu")]},
    "romance": {
        "do": ("Someone you have never met who asks for money is the mark of a romance scam. Ask for a live video call and tell a friend before you do anything",
               "Une personne jamais rencontrée qui demande de l'argent, c'est la marque d'une arnaque sentimentale. Demandez un appel vidéo en direct et parlez-en à un proche avant d'agir"),
        "dont": [("Do not send money, airtime or gift cards to someone you only know online", "N'envoyez ni argent, ni crédit, ni cartes cadeaux à quelqu'un que vous ne connaissez qu'en ligne"),
                 ("Do not send intimate photos or videos: they are used for blackmail", "N'envoyez pas de photos ou vidéos intimes : elles servent au chantage")]},
    "extortion": {
        "do": ("Keep the messages as proof, tell someone you trust, and report it at the nearest police station or gendarmerie brigade",
               "Gardez les messages comme preuve, parlez-en à une personne de confiance, et signalez-le au commissariat ou à la brigade de gendarmerie la plus proche"),
        "dont": [("Do not pay: paying once brings more demands", "Ne payez pas : payer une fois amène d'autres demandes"),
                 ("Do not send more photos or personal details", "N'envoyez plus de photos ni d'informations personnelles")]},
    "rental": {
        "do": ("Visit the place yourself and meet the owner in person, with a witness, before you pay anything", "Visitez le logement vous-même et rencontrez le propriétaire en personne, avec un témoin, avant de payer quoi que ce soit"),
        "dont": [("Do not pay rent or a deposit by mobile money before you have seen the place and signed a contract", "Ne payez ni loyer ni caution par mobile money avant d'avoir vu le logement et signé un contrat")]},
    "charity": {
        "do": ("Give only through an organisation you can visit, or call on a number you find yourself", "Donnez seulement par une organisation que vous pouvez visiter, ou appeler à un numéro que vous trouvez vous-même"),
        "dont": [("Do not send money to a personal mobile money number for a collection you cannot check", "N'envoyez pas d'argent à un numéro mobile money personnel pour une collecte que vous ne pouvez pas vérifier")]},
    "official": {
        "do": ("Real offices do not collect fines or fees through a personal mobile money number. Go to the office yourself, or call a number you find on its official site",
               "Les vrais services ne perçoivent pas d'amende ni de frais sur un numéro mobile money personnel. Rendez-vous au bureau, ou appelez un numéro trouvé sur son site officiel"),
        "dont": [("Do not pay a fine, a fee or a 'settlement' to an individual", "Ne payez ni amende, ni frais, ni « arrangement » à un particulier")]},
    "advance_fee": {
        "do": ("Money that is really yours never needs a fee paid first. Ask the bank or body named, on a number you find yourself",
               "Un argent qui vous revient vraiment ne demande jamais de frais d'abord. Renseignez-vous auprès de la banque ou de l'organisme cité, sur un numéro que vous trouvez vous-même"),
        "dont": [("Do not pay any fee to release funds, an inheritance, a grant or a parcel", "Ne payez aucun frais pour débloquer des fonds, un héritage, une subvention ou un colis")]},
    "phishing": {
        "do": ("Open the app, or type the official address yourself. Never go through the link in the message",
               "Ouvrez l'application, ou tapez vous-même l'adresse officielle. Ne passez jamais par le lien du message"),
        "dont": [("Do not type your password or a code on a page you reached from a message", "Ne tapez ni mot de passe ni code sur une page ouverte depuis un message")]},
    "fake_page": {
        "do": ("Look for the real page or site of that person or body yourself, the one that has existed for years, and compare",
               "Cherchez vous-même la vraie page ou le vrai site de cette personne ou de cet organisme, celui qui existe depuis des années, et comparez"),
        "dont": [("Do not pay or send documents to a page you cannot confirm", "Ne payez pas et n'envoyez pas de documents à une page que vous ne pouvez pas confirmer")]},
}

JOB_SAFETY = ("Before you go anywhere: ask for the employer's name and address, meet first in a public place, and tell someone you trust where you are going and who you are meeting",
              "Avant d'aller quelque part : demandez le nom et l'adresse de l'employeur, rencontrez-le d'abord dans un lieu public, et dites à une personne de confiance où vous allez et qui vous rencontrez")

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


# how scams are worded beyond the first lists: used only to name the kind of scam, never to clear a message
NAMING_HINTS = {
    "job": r"shortlisted?|position of|poste de|poste d'|\bposte\b|interview slot|entretien|uniform|medical test|visite m[ée]dicale|applicant|candidature retenue|travail [àa] l'[ée]tranger|work abroad",
    "romance": r"us army|\barmy\b|soldier|soldat|sergeant|\bsgt\b|peacekeep\w*|trunk box|inherit\w*|h[ée]ritage|saw your profile|something special|my dear|mon c[œo]eur|ma belle|mon ch[ée]ri|tr[èe]s belle|you are (?:very )?beautiful|"
               r"talking for \d+|been talking|doctor with the (?:un|army)|i think i love|gift parcel",
    "family": r"new number|nouveau num[ée]ro|changed my number|chang[ée] de num[ée]ro|phone (?:don )?spoil|\bna me\b|t[ée]l[ée]phone (?:est )?(?:cass[ée]|perdu)|lost my phone|\buncle\b|\btonton\b",
    "exam": r"(?:questions?|papers?|sujets?|[ée]preuves?)\W+(?:\w+\W+){0,3}(?:leaked|fuit[ée]s?|d'avance)|\bgce\b|probatoire|baccalaur[ée]at|\bbepc\b",
    "credential": r"\bpuk\b|sim (?:card|swap)|votre sim|carte sim",
    "seller": r"\bdhl\b|fedex|\bups\b|chronopost|colissimo|stockage|storage fee|re-?delivery|reschedule|frais de (?:douane|livraison|stockage)|delivery fee|colis (?:est )?bloqu[ée]|parcel (?:is )?(?:held|blocked)",
    "reversal": r"mauvais num[ée]ro|\bfloat\b|rends-?moi|rendez-?moi|garde le reste|keep the rest",
}


SCHEME_GUIDE = {
    "visa_scholarship": "a fake visa, green-card lottery, study-abroad or scholarship offer that asks for money",
    "job": "a fake job or recruitment offer (fee, medical test, uniform, visa fee, documents), including work abroad",
    "exam": "a fake concours, admission or exam offer, leaked exam papers, grade fixing",
    "investment": "an investment, trading, crypto, forex, mining or referral platform, or money doubling",
    "loan": "a loan offer that asks for a fee first",
    "reversal": "'money sent by mistake' or a fake credit receipt, asking you to send money back or cash",
    "credential": "someone after your PIN, OTP, password, SIM or account (fake bank, operator, agent or customer service)",
    "prize": "a fake prize, lottery, raffle, gift or promotion",
    "seller": "a fake seller, delivery, parcel or customs or storage fee",
    "family": "a fake emergency or request from a relative or friend (new number, hospital, stranded)",
    "romance": "a romance or relationship story that leads to money or a parcel (soldier, doctor abroad)",
    "extortion": "blackmail or threats (intimate photos, kidnapping)",
    "official": "someone posing as police, tax, court, immigration or another official",
    "advance_fee": "a fee demanded before a payout that fits none of the others",
    "phishing": "a link made to steal your login",
    "rental": "a house, room or rental deposit scam",
    "charity": "a fake charity or donation appeal",
    "fake_page": "a fake page, account or document using a known name",
}


def scheme_of(text: str, scam_types: list[str], model_scheme: str = "") -> str | None:
    """What this message itself says weighs most; the analyst's reading next; the types of similar old
    reports only break ties, since a neighbour can be a different scheme."""
    best, top = None, 0
    picked = (model_scheme or "").strip().lower()
    for name, (rx, _, _) in SCHEMES.items():
        rx = rf"(?<![^\W_])(?:{rx}" + (f"|{NAMING_HINTS[name]}" if name in NAMING_HINTS else "") + ")"  # words start where a word starts; stems like "recrut" still take any ending
        direct = 2 * len(re.findall(rx, text, flags=re.I)) + 2 * len(re.findall(rx, model_scheme or "", flags=re.I))
        if picked == name:
            direct += 5
        if not direct:
            continue  # neighbours can break a tie, never name a scheme the message itself does not show
        n = direct + len(re.findall(rx, " ".join(scam_types or []), flags=re.I))
        if n > top:
            best, top = name, n
    return best


def announcement(text: str) -> bool:
    """A job, concours or scholarship announcement, judged among the first version's schemes only:
    the newer names (romance, official...) describe a scam better but must not change this rule."""
    counts = {}
    for name in ("visa_scholarship", "job", "exam", "investment", "loan", "reversal", "credential", "prize", "seller", "family"):
        n = len(re.findall(rf"(?<![^\W_])(?:{SCHEMES[name][0]})", text, flags=re.I))
        key = "job" if name == "exam" else name  # a concours counted as a job offer then, and still does here
        counts[key] = counts.get(key, 0) + n
    best = max(counts, key=lambda k: counts[k])  # ties go to the earlier scheme, as before
    return counts[best] > 0 and best in ("visa_scholarship", "job")


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
    if verdict == "looks_genuine" and facts.get("announcement"):
        do.append(("Apply only through the organisation's own address or website", "Postulez seulement par l'adresse ou le site de l'organisme")[i])
        do.append(("If anyone later asks you to pay to apply, or to send money for a file, a test or a uniform, stop: that part would be a scam",
                   "Si quelqu'un vous demande ensuite de payer pour postuler, ou d'envoyer de l'argent pour un dossier, un test ou une tenue, arrêtez : ce serait une arnaque")[i])
        return do, dont
    if verdict == "cant_tell" and facts.get("announcement"):
        do.append(("Find this offer yourself on the organisation's official website or at its office before you apply",
                   "Retrouvez vous-même cette offre sur le site officiel de l'organisme ou à son bureau avant de postuler")[i])
        dont.append(("Never pay to apply, and do not send your ID or diplomas until you have confirmed the offer",
                     "Ne payez jamais pour postuler, et n'envoyez ni pièce d'identité ni diplômes avant d'avoir confirmé l'offre")[i])
        return do, dont
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
    if claimed and scheme in ANNOUNCEMENTS:
        # the institution the message names, and the only site that can speak for it
        do.append((f"Check on the official site of {claimed[0]} yourself ({claimed[1][0]}). Real programmes never recruit through WhatsApp or Telegram links, and never ask for fees by mobile money",
                   f"Vérifiez vous-même sur le site officiel de {claimed[0]} ({claimed[1][0]}). Les vrais programmes ne recrutent jamais par lien WhatsApp ou Telegram, et ne demandent jamais de frais par mobile money")[i])
    elif plan.get("do"):
        do.append(plan["do"][i])
    money_scheme = scheme in ("reversal", "credential", None) or brand is not None
    if brand and money_scheme:
        do.append(OPERATOR[brand][lang if lang in ("en", "fr") else "en"])
    if scheme == "job" and facts.get("body_numbers"):
        do.append(JOB_SAFETY[i])  # an employer who is only a phone number: how to check it before you go
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


# ---------------------------------------------------------------------------------------------------------------
# What to do depends on what the person has already done. The reader says it ("I paid", "I gave my code"), the
# fixed lines below name only official channels, and a model may add at most two lines that pass the same checks.
ACTED = ("nothing", "clicked", "code", "money", "documents", "installed")

AFTER = {
    "money": [
        ("Act within the hour: tell your operator or bank that the transfer was fraud, using its official line, and ask them to block the receiving number and the transaction",
         "Agissez dans l'heure : dites à votre opérateur ou à votre banque que le transfert est une fraude, par sa ligne officielle, et demandez de bloquer le numéro receveur et la transaction"),
        ("Keep the transaction ID, the receiving number and a screenshot of the conversation. Do not delete anything",
         "Gardez l'identifiant de la transaction, le numéro receveur et une capture de la conversation. Ne supprimez rien"),
        ("Report it to the police or gendarmerie with those proofs. Anyone who offers to recover your money for a fee is a second scam",
         "Déclarez-le à la police ou à la gendarmerie avec ces preuves. Toute personne qui propose de récupérer votre argent contre des frais est une deuxième arnaque"),
    ],
    "code": [
        ("Change your Mobile Money PIN now, from your phone's own menu, then check your last transactions",
         "Changez votre code secret Mobile Money maintenant, depuis le menu de votre téléphone, puis vérifiez vos dernières transactions"),
        ("If the code was for an app or account, change that password and sign out of all other devices",
         "Si le code était celui d'une application ou d'un compte, changez ce mot de passe et déconnectez tous les autres appareils"),
        ("Tell your operator or bank that someone has your code, through its official line",
         "Dites à votre opérateur ou à votre banque que quelqu'un a votre code, par sa ligne officielle"),
    ],
    "clicked": [
        ("Close the page without typing anything. If you already typed a password or code, change it now from the real app or site you type yourself",
         "Fermez la page sans rien taper. Si vous avez déjà tapé un mot de passe ou un code, changez-le maintenant depuis la vraie application ou le vrai site que vous tapez vous-même"),
        ("Check your balance and recent activity for anything you did not do",
         "Vérifiez votre solde et votre activité récente pour toute opération que vous n'avez pas faite"),
    ],
    "documents": [
        ("Keep a copy of what you sent and to whom. Your ID can be used to open accounts or SIM cards in your name",
         "Gardez une copie de ce que vous avez envoyé et à qui. Votre pièce d'identité peut servir à ouvrir des comptes ou des lignes à votre nom"),
        ("Tell your operator and bank that your ID may be misused, and be wary of calls that quote your own details back to you",
         "Dites à votre opérateur et à votre banque que votre pièce d'identité peut être utilisée à mauvais escient, et méfiez-vous des appels qui vous citent vos propres informations"),
    ],
    "installed": [
        ("Uninstall the app now and switch off any permission it asked for. Do not open it again",
         "Désinstallez l'application maintenant et coupez toutes les autorisations demandées. Ne la rouvrez pas"),
        ("From another device, change the passwords of your email, Mobile Money and social accounts",
         "Depuis un autre appareil, changez les mots de passe de votre courriel, de votre Mobile Money et de vos réseaux sociaux"),
    ],
}


def after_action(acted: str, brands: list[str], lang: str) -> list[str]:
    """Fixed, official-only steps for what the person already did, first. The operator's own line goes in when known."""
    if acted not in AFTER:
        return []
    i = 1 if lang == "fr" else 0
    out = [s[i] for s in AFTER[acted]]
    brand = next((b for b in brands if b in OPERATOR), None)
    if brand and acted in ("money", "code"):
        out.insert(1, OPERATOR[brand][lang if lang in ("en", "fr") else "en"])
    return out


_NUM = re.compile(r"\d[\d ]{2,}\d|\*\d[\d*]*#|#\d[\d*]*#|https?://\S+|www\.\S+|\b[\w-]+\.(?:com|cm|net|org|app|me|top)\b", re.I)


def allowed_tokens() -> set[str]:
    """Every number, code and site a card may name: the operators' own lines and the official list, nothing else."""
    ok = set()
    for line in OPERATOR.values():
        for t in line.values():
            ok |= {re.sub(r"\s", "", m) for m in _NUM.findall(t)}
    return ok


def vetted(line: str) -> bool:
    """A model-written step is kept only if it invents no phone number, code or site, is short, and promises nothing."""
    if not line or len(line) > 220:
        return False
    if any(re.sub(r"\s", "", m) not in allowed_tokens() for m in _NUM.findall(line)):
        return False
    return not re.search(r"(?i)\b(guarantee|garanti\w*|you will (?:get|recover)|vous (?:r[ée]cup[ée]rerez|serez rembours))", line)
