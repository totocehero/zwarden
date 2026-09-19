# Zwarden

Extension navigateur de gestion de mots de passe, open source, compatible
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) et l'API Bitwarden.

Objectif : la même compatibilité, un ordre de grandeur en moins de poids.

## Pourquoi

L'extension Bitwarden officielle (2026.7.0) mesurée sur disque — **46,4 Mo**
décompressée, hors sourcemaps :

| Poste | Taille | Conséquence |
|---|---|---|
| `background.js` | 3,3 Mo | service worker MV3 tué après 30 s d'inactivité → 3,3 Mo reparsés à chaque réveil |
| module WASM (SDK Rust) | 7,4 Mo **× 2** | chargé au démarrage — et le paquet contient deux copies **octet pour octet identiques** |
| bundles d'autofill (`bootstrap-autofill-overlay*.js` × 3) | 4,9 Mo | candidats à l'injection dans les pages visitées ; le « détecteur » à `document_start` est en réalité un déclencheur inconditionnel de 164 octets, sans détection de formulaire |
| popup Angular (JS + CSS) | 6,7 Mo | plusieurs centaines de ms avant le premier rendu |
| traductions (63 locales) | 15 Mo | embarquées intégralement, quelle que soit la langue |

Zwarden vise **< 300 Ko** au total.

Les leviers, dans l'ordre d'impact :

1. **WebCrypto natif** plutôt qu'un SDK Rust compilé en WASM. AES-256-CBC,
   HMAC-SHA256, PBKDF2-SHA256 et SHA-2 sont déjà dans le navigateur : natifs,
   à temps constant, audités, et 0 octet de bundle. Seul Argon2id nécessite du
   WASM (~45 Ko), chargé en import dynamique et uniquement au déverrouillage
   d'un compte configuré ainsi.
2. **Autofill en deux étages** : un détecteur de formulaire léger à
   `document_start`, le moteur d'autofill injecté seulement quand un champ
   pertinent est détecté.
3. **Preact** (~10 Ko de runtime) au lieu d'Angular.
4. **Service worker mince** : logique lourde en modules dynamiques, état
   volatil en `chrome.storage.session`.

## État

Le noyau cryptographique est implémenté et testé. Le reste est en cours.

- [x] Encodage (base64, UTF-8, comparaison à temps constant)
- [x] `EncString` — analyse et sérialisation des 7 types Bitwarden
- [x] `SymmetricCryptoKey` — clés 32/64 octets
- [x] AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC
- [x] Dérivation de clé : PBKDF2-SHA256 et Argon2id
- [x] 267 tests, dont les vecteurs RFC 4231 / 5869 / 6238 / 7914
- [x] **Interopérabilité validée contre Vaultwarden 2026.6.0** — authentification,
      déchiffrement de la clé de coffre, et aller-retour écriture/lecture complet
- [x] Client API : prelogin, authentification, rafraîchissement de session,
      synchronisation, création et suppression d'items — sans jamais voir ni
      clé ni mot de passe
- [x] Couche coffre : orchestrateur de déverrouillage (`unlock()`, hygiène
      mémoire incluse) et déchiffrement d'items (clé par item, vues
      partielles, casse tolérée)
- [ ] Service worker et cycle de vie du verrouillage
- [ ] Popup (déverrouillage, liste, recherche, copie) — deux vues commutables :
      « Bitwarden-like » (disposition classique, zéro réapprentissage pour les
      migrants) et « Zwarden » (filtrée sur l'onglet actif, pilotage clavier)
- [x] Coffres d'organisation : clé privée RSA et clés d'organisation
      déballées, items partagés lisibles
- [x] Tags : dossiers et collections déchiffrés, chips filtrantes (phase 1/3
      — assignation puis partage par tag à venir)
- [x] Remplissage depuis la popup — geste explicite, correspondance
      d'origine stricte
- [x] Édition d'items depuis la popup — champs préservés, clé d'item et
      clés d'organisation respectées, historique de mots de passe
- [x] Items récemment utilisés en tête de liste
- [x] Proposition d'enregistrer un identifiant saisi sur un site inconnu —
      pastille sur l'icône, décision dans la popup, rien d'injecté dans la page
- [x] Codes TOTP sur les lignes du coffre — vecteurs RFC 6238 rejoués
      (SHA-1/256/512), `otpauth://` analysée, décompte et copie
- [x] Générateur de mots de passe — tirage sans biais, composition garantie
- [x] Garde par item (`reprompt`) — un item marqué « redemander le mot de passe
      maître » ne livre aucun secret sans une nouvelle saisie, vérifiée hors
      réseau
- [ ] Création d'items depuis la popup (formulaire complet)
- [ ] Autofill automatique (détection de formulaire, suggestion en page)

## Modèle de sécurité

Le serveur est traité comme **non fiable**. Il ne voit jamais ni le mot de passe
maître, ni la clé maître, ni aucun contenu en clair.

Décisions notables, dont certaines sont plus strictes que Bitwarden :

- **MAC vérifié avant tout déchiffrement.** Le ciphertext ne touche jamais AES
  si le HMAC ne correspond pas — c'est ce qui ferme les oracles de padding sur
  CBC. La comparaison est à temps constant.
- **Refus des rétrogradations.** Une donnée de type 2 (authentifiée) présentée
  comme type 0 (non authentifiée) est rejetée. Sans cela, un serveur hostile
  peut dépouiller le MAC et retrouver un oracle de padding.
- **Écriture toujours authentifiée.** Chiffrer avec une clé sans `macKey` lève
  une erreur. Le type 0 reste lisible pour la migration d'anciens coffres.
- **Paramètres KDF validés, dans les deux sens.** `iterations` et `memory`
  viennent du serveur *avant* authentification : un serveur compromis peut
  annoncer 1 itération pour rendre la clé maître triviale à casser hors ligne —
  ou des valeurs absurdes (2³¹ itérations, mémoire Argon2 en gibioctets) pour
  geler le client au déverrouillage. Zwarden rejette les configurations sous le
  plancher OWASP, au-dessus des maxima du client officiel, et les valeurs non
  entières. Bitwarden ne fait aucune de ces vérifications.
- **AES-128 (type 1) refusé** en déchiffrement : ré-chiffrement requis.

## Compatibilité

Format de chiffrement identique à Bitwarden, donc les coffres sont
interopérables dans les deux sens :

```
2.<iv b64>|<ciphertext b64>|<mac b64>
```

- clé maître : `PBKDF2-SHA256(mdp, e-mail normalisé, n)` ou `Argon2id(mdp, SHA-256(e-mail))`
- clé étirée : `HKDF-Expand(clé maître, "enc"|"mac")` — Expand seul, sans Extract
- hash serveur : `PBKDF2-SHA256(clé maître, mdp, 1 itération)`

## Développement

```bash
npm install
npm test          # 267 tests
npm run typecheck # TypeScript strict
npm run lint      # ESLint : promesses perdues, comparaisons laxistes
npm run build
npm run size      # budget de poids de dist/
```

## Documentation

- [`docs/CRYPTO.md`](docs/CRYPTO.md) — modèle de menace, hiérarchie des clés,
  schéma de chiffrement, durcissements et leurs justifications.
- [`docs/EXTENSION.md`](docs/EXTENSION.md) — décisions d'ergonomie et de
  sécurité de l'extension : déverrouillage, cycle de verrouillage, deux vues
  de popup, règles d'autofill.

## Licence

AGPL-3.0-only — voir [`LICENSE`](LICENSE).
