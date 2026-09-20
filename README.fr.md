# Zwarden

*[English](README.md)*

Un gestionnaire de mots de passe libre pour navigateur, compatible avec
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) et l'API Bitwarden.

L'objectif : la même compatibilité, un ordre de grandeur de moins sur la balance.

## D'où vient ce code

**Ce dépôt ne contient aucune ligne écrite par un humain.** Le code, les tests et
la documentation ont été produits entièrement par un modèle de langage (Claude),
sous direction humaine : périmètre, arbitrages et validation. Les mentions
`Co-Authored-By` des commits en gardent la trace.

Ce que cela implique, dit franchement : les choix cryptographiques sont vérifiés
contre les vecteurs officiels (RFC 4231 / 5869 / 6238 / 7914) et par un
aller-retour d'interopérabilité contre un vrai Vaultwarden, mais **aucun audit de
sécurité humain indépendant n'a été mené**. Pour un gestionnaire de mots de
passe, c'est un fait auquel vous avez droit avant de lui confier un coffre.

## Pourquoi

L'extension Bitwarden officielle (2026.7.0), mesurée sur le disque — **46,4 Mo**
décompressés, hors source maps :

| Élément | Taille | Conséquence |
|---|---|---|
| `background.js` | 3,3 Mo | un service worker MV3 tué après 30 s d'inactivité → 3,3 Mo réanalysés à chaque réveil |
| module WASM (SDK Rust) | 7,4 Mo **× 2** | chargé au démarrage — et le paquet en contient deux copies **identiques octet pour octet** |
| bundles d'autofill (`bootstrap-autofill-overlay*.js` × 3) | 4,9 Mo | candidats à l'injection dans les pages visitées ; le « détecteur » de `document_start` est en réalité un déclencheur inconditionnel de 164 octets, sans aucune détection de formulaire |
| popup Angular (JS + CSS) | 6,7 Mo | plusieurs centaines de ms avant le premier rendu |
| traductions (63 langues) | 15 Mo | livrées en entier, quelle que soit la langue |

Zwarden vise **moins de 300 Ko** au total.

Les leviers, par ordre d'impact :

1. **WebCrypto natif** plutôt qu'un SDK Rust compilé en WASM. AES-256-CBC,
   HMAC-SHA256, PBKDF2-SHA256 et SHA-2 sont déjà dans le navigateur : natifs, à
   temps constant, audités, et 0 octet de bundle. Seul Argon2id exige du WASM
   (~45 Ko), chargé par import dynamique et uniquement au déverrouillage d'un
   compte configuré ainsi.
2. **Autofill en deux étages** : un détecteur de formulaire léger à
   `document_start`, le moteur de remplissage injecté seulement une fois un
   champ pertinent détecté.
3. **Preact** (~10 Ko de runtime) au lieu d'Angular.
4. **Un service worker mince** : logique lourde en modules dynamiques, état
   volatile dans `chrome.storage.session`.

## État

Le cœur cryptographique est implémenté et testé. Le reste avance.

- [x] Encodage (base64, UTF-8, comparaison à temps constant)
- [x] `EncString` — analyse et sérialisation des 7 types de Bitwarden
- [x] `SymmetricCryptoKey` — clés de 32/64 octets
- [x] AES-256-CBC + HMAC-SHA256, encrypt-then-MAC
- [x] Dérivation de clé : PBKDF2-SHA256 et Argon2id
- [x] 674 tests, dont les vecteurs des RFC 4231 / 5869 / 6238 / 7914
- [x] **Interopérabilité validée contre Vaultwarden 2026.6.0** —
      authentification, déchiffrement de la clé de coffre, et un aller-retour
      complet d'écriture/lecture
- [x] Client d'API : prelogin, authentification, rafraîchissement de session,
      synchronisation, création et suppression d'éléments — sans jamais voir une
      clé ni un mot de passe
- [x] Couche coffre : l'orchestrateur de déverrouillage (`unlock()`, hygiène
      mémoire comprise) et le déchiffrement des éléments (clé par élément, vues
      partielles, tolérance à la casse)
- [x] Service worker et cycle de verrouillage — inactivité, verrouillage de la
      session de l'ordinateur, fermeture du navigateur
- [x] Popup : déverrouillage, liste, recherche, copie
- [ ] Deux vues de popup commutables : « à la Bitwarden » (la disposition
      classique, rien à réapprendre pour qui migre) et « Zwarden » (filtrée sur
      l'onglet actif, pilotée au clavier). Une seule vue aujourd'hui, la seconde
      reste à faire
- [x] Coffres d'organisation : clé privée RSA et clés d'organisation
      désenveloppées, éléments partagés lisibles
- [x] Étiquettes : dossiers et collections déchiffrés, puces de filtrage
      (phase 1 sur 3 — l'affectation puis le partage par étiquette suivront)
- [x] Remplissage depuis la popup — un geste explicite, correspondance stricte
      d'origine
- [x] Édition d'éléments depuis la popup — champs préservés, clé d'élément et
      clés d'organisation respectées, historique des mots de passe
- [x] Éléments récemment utilisés en tête de liste
- [x] Proposition d'enregistrer un identifiant saisi sur un site inconnu — une
      pastille sur l'icône, la décision dans la popup, rien d'injecté dans la
      page
- [x] Codes TOTP sur les lignes du coffre — vecteurs RFC 6238 rejoués
      (SHA-1/256/512), `otpauth://` analysé, compte à rebours et copie
- [x] Générateur de mots de passe — tirage sans biais, composition garantie
- [x] Garde par élément (`reprompt`) — un élément marqué « redemander le mot de
      passe maître » ne livre aucun secret sans une nouvelle saisie, vérifiée
      hors ligne
- [x] Raccourcis clavier — ouvrir, générer et copier, verrouiller
- [x] Effacement du presse-papiers qui survit à la fermeture de la popup
      (document offscreen + alarme)
- [x] Création d'éléments depuis la popup — identifiant, carte bancaire,
      identité ou note sécurisée
- [x] Cartes bancaires et identités, poussées plus loin que celles de Bitwarden :
      le réseau déduit du numéro au lieu d'être choisi dans une liste, la clé de
      contrôle vérifiée à la frappe, l'échéance comparée à aujourd'hui, le numéro
      copié en chiffres nus, le nom complet et l'adresse postale composés et
      copiés d'un geste, les papiers masqués, et la liste affichant
      `Visa •••• 4242` sans jamais détenir de numéro débitable
- [x] La langue et le thème du navigateur suivis — `chrome.i18n` et une icône de
      barre d'outils qui s'inverse sur fond clair
- [x] Une langue que l'utilisateur peut choisir, à rebours d'une API qui ne le
      permet pas : `chrome.i18n` lit la langue du navigateur et rien ne peut en
      changer, le catalogue choisi est donc chargé à la main. Ajouter une langue
      tient en un dossier (`node scripts/new-locale.mjs <code>`), vérifié
      automatiquement par la suite de tests, et chargé uniquement pour ceux qui
      le lisent — ce qui est tout l'argument contre la livraison de 63
      traductions à tout le monde
- [x] Filtrage de la liste par type d'élément, plusieurs types à la fois
- [x] Vérification optionnelle des fuites auprès de Have I Been Pwned,
      **désactivée par défaut** et seule chose ici qui parle à quelqu'un
      d'autre que votre serveur. Le mot de passe ne sort pas, ni son empreinte
      complète : cinq caractères hexadécimaux de son SHA-1 partent, quelque
      huit cents suffixes reviennent, la comparaison se fait localement. Ce que
      ça laisse fuir est écrit dans les paramètres, pas résumé en rassurance
- [x] Un export chiffré — Argon2id puis AES-256-GCM, les paramètres
      authentifiés avec le chiffré : les abaisser fait refuser l'ouverture
      plutôt qu'ouvrir plus faible. **Il n'existe pas d'export en clair** : un
      tel fichier finit dans un dossier de téléchargements, dans chaque
      sauvegarde, et sur le disque le jour où il est revendu. Dedans, la forme
      d'import de Bitwarden — un coffre qu'on ne peut pas emporter ailleurs est
      un coffre où l'on est enfermé
- [x] Un rapport de santé, calculé entièrement sur la machine — mots de passe
      réutilisés, faibles, ceux qui reprennent simplement le site ou le compte,
      ceux inchangés depuis un an, cartes arrivées à échéance. Aucun
      dictionnaire, aucun réseau, aucun tiers. Les éléments gardés par
      `reprompt` ne sont **pas examinés** et le rapport dit combien, un agrégat
      sur un mot de passe en disant autant qu'une copie
- [x] Édition hors ligne : une écriture que le serveur n'a jamais reçue est mise
      de côté — déjà chiffrée, jamais l'édition en clair — et envoyée dès qu'il
      est joignable. Une écriture en attente n'est **jamais rejouée par-dessus
      un élément qui a changé depuis** : l'utilisateur est prévenu plutôt qu'un
      mot de passe renouvelé soit silencieusement remis
- [x] Le premier écran déchiffré en premier — l'ordre se calcule à partir des
      identifiants, qui ne sont pas chiffrés, si bien que les vingt lignes que
      montre la popup sont les vingt déchiffrées avant qu'elle ne dessine. Un
      coffre de 500 éléments avec une clé propre à chacun coûte ~650 ms à
      déchiffrer en entier ; la liste ne l'attend plus
- [x] Passkeys : **créer et utiliser** celles du coffre. Le site qu'une page a le
      droit de réclamer est vérifié ici, puisque intercepter
      `navigator.credentials.get()` retire cette vérification au navigateur.
      Désactivé par défaut — c'est la seule fonctionnalité qui place du code
      dans chaque page, et encore : le remplacement d'une fonction, rien de
      dessiné, la confirmation dans la popup. Quand Zwarden n'a rien à
      proposer, le navigateur reprend la main et une clé matérielle marche
      toujours
- [ ] Dérivation de clé dans le service worker (une popup sans clé) — et, avec
      elle, le raccourci de remplissage
- [ ] Remplissage automatique (détection de formulaire, suggestion dans la page)

## Modèle de sécurité

Le serveur est traité comme **non fiable**. Il ne voit jamais le mot de passe
maître, la clé maîtresse, ni le moindre contenu en clair.

Quelques décisions, dont certaines plus strictes que celles de Bitwarden :

- **Le MAC est vérifié avant tout déchiffrement.** Un chiffré ne touche jamais
  AES si le HMAC ne correspond pas — c'est ce qui ferme les oracles de
  remplissage sur CBC. La comparaison est à temps constant.
- **Le déclassement est refusé.** Une donnée de type 2 (authentifiée) présentée
  comme du type 0 (non authentifiée) est rejetée. Sans cela, un serveur hostile
  peut retirer le MAC et retrouver un oracle de remplissage.
- **Les écritures sont toujours authentifiées.** Chiffrer avec une clé dépourvue
  de `macKey` lève une erreur. Le type 0 reste lisible, pour migrer les vieux
  coffres.
- **Paramètres de KDF validés, dans les deux sens.** `iterations` et `memory`
  viennent du serveur *avant* l'authentification : un serveur compromis peut
  annoncer 1 itération pour rendre la clé maîtresse triviale à casser hors
  ligne — ou des valeurs absurdes (2³¹ itérations, mémoire Argon2 en gibioctets)
  pour figer le client au déverrouillage. Zwarden rejette les configurations
  sous le plancher OWASP, au-dessus des maxima du client officiel, et les
  valeurs non entières. Bitwarden ne fait ni l'une ni l'autre vérification.
- **AES-128 (type 1) refusé** au déchiffrement : rechiffrement exigé.

## Compatibilité

Le format de chiffrement est identique à celui de Bitwarden, les coffres sont
donc interopérables dans les deux sens :

```
2.<iv b64>|<chiffré b64>|<mac b64>
```

- clé maîtresse : `PBKDF2-SHA256(mdp, courriel normalisé, n)` ou `Argon2id(mdp, SHA-256(courriel))`
- clé étirée : `HKDF-Expand(clé maîtresse, "enc"|"mac")` — Expand seul, pas d'Extract
- empreinte serveur : `PBKDF2-SHA256(clé maîtresse, mdp, 1 itération)`

## Développement

```bash
npm install
npm test          # 674 tests
npm run typecheck # TypeScript strict
npm run lint      # ESLint : promesses perdues, comparaisons laxistes
npm run build
npm run size      # budget de taille pour dist/
```

## Documentation

La documentation technique de fond n'est maintenue qu'en anglais : la traduire
doublerait la charge d'entretien de 750 lignes de référence, pour deux versions
qui divergeraient à la première correction.

- [`docs/CRYPTO.md`](docs/CRYPTO.md) — modèle de menace, hiérarchie des clés,
  schéma de chiffrement, mesures de durcissement et leur raisonnement.
- [`docs/EXTENSION.md`](docs/EXTENSION.md) — les décisions d'ergonomie et de
  sécurité de l'extension : déverrouillage, cycle de verrouillage, les deux vues
  de popup, les règles de remplissage.
- [`docs/STORAGE.md`](docs/STORAGE.md) — ce qui est stocké où, et ce qu'obtient
  réellement un attaquant qui atteint chaque espace. Écrit à l'envers, depuis
  les capacités de l'attaquant plutôt que depuis la liste des fonctions.

## Licence

AGPL-3.0-only — voir [`LICENSE`](LICENSE).
