# Cryptographie de Zwarden

Ce document décrit le schéma cryptographique implémenté dans `src/core/crypto/`.
Il vise deux publics : quiconque audite le code, et quiconque devra le modifier
dans six mois.

Zwarden est **compatible avec le format Bitwarden / Vaultwarden**. Les
divergences volontaires sont signalées par ⚠ et concernent uniquement des
durcissements, jamais le format sur le fil.

---

## 1. Modèle de menace

### Ce dont Zwarden protège

| Adversaire | Capacité supposée | Protection |
|---|---|---|
| Serveur malveillant ou compromis | Lit et modifie tout ce qu'il stocke, contrôle ses réponses | Chiffrement de bout en bout ; authentification de chaque champ ; validation des paramètres KDF |
| Réseau (MITM) | Lit et modifie le trafic | TLS, plus le chiffrement de bout en bout en défense en profondeur |
| Vol de la base serveur | Lecture hors ligne de tout le stockage | Le serveur ne détient aucune clé ; seule une attaque par dictionnaire sur le mot de passe maître reste possible, freinée par le KDF |
| Vol du profil navigateur, coffre verrouillé | Lecture du stockage local persistant | Aucune clé en clair sur disque |

### Ce dont Zwarden ne protège pas

Ces limites sont structurelles, communes à tous les gestionnaires de mots de
passe en extension. Les énoncer évite de fausses attentes.

- **Machine compromise, coffre déverrouillé.** La clé du coffre est en mémoire.
  Un malware avec accès au processus la récupère. `wipe()` réduit la fenêtre
  d'exposition, sans plus.
- **Mot de passe maître faible.** Le KDF augmente le coût d'une attaque hors
  ligne ; il ne compense pas un mot de passe devinable.
- **Extension navigateur malveillante** disposant des mêmes permissions.
- **Métadonnées.** Le serveur connaît le nombre d'items, leurs dates de
  modification et leur taille approximative. Ces informations ne sont pas
  chiffrées dans le format Bitwarden.

---

## 2. Hiérarchie des clés

```
                       mot de passe maître
                              │
              ┌───────────────┴───────────────┐
              │ KDF                           │
              │ sel = e-mail normalisé        │
              ▼                               │
       clé maître (32 o)                      │
              │                               │
      ┌───────┴────────┐                      │
      │ HKDF-Expand    │ PBKDF2               │
      │ "enc" / "mac"  │ 1 ou 2 itérations    │
      ▼                ▼                      │
 clé maître        hash du mot de passe ──────┘
 étirée (64 o)     (envoyé au serveur)
      │
      │ déchiffre le champ `Key` du profil
      ▼
 clé du coffre (64 o)  ← aléatoire, indépendante du mot de passe
      │
      ├── déchiffre les champs de chaque item
      └── déchiffre la clé privée RSA (partage en organisation)
```

### Pourquoi cette indirection

La clé maître **ne chiffre jamais de données**. Elle ne sert qu'à envelopper la
clé du coffre.

Conséquence directe : changer de mot de passe maître ne demande que de
ré-envelopper 64 octets. Sans cette indirection, il faudrait re-chiffrer et
retransmettre l'intégralité du coffre à chaque changement — coûteux, et surtout
fragile en cas d'interruption au milieu de l'opération.

---

## 3. Dérivation de la clé maître

### PBKDF2-SHA256

```
clé maître = PBKDF2-SHA256(
    password = NFKD(mot de passe),
    salt     = lowercase(trim(e-mail)),
    c        = itérations annoncées par le serveur,
    dkLen    = 32
)
```

### Argon2id

```
clé maître = Argon2id(
    password    = NFKD(mot de passe),
    salt        = SHA-256(lowercase(trim(e-mail))),
    t           = itérations,
    m           = mémoire en MiB × 1024,
    p           = parallélisme,
    hashLength  = 32
)
```

Le sel est le **condensat** de l'e-mail, pas l'e-mail brut : Argon2 impose une
taille de sel fixe.

### Détails qui cassent l'interopérabilité s'ils divergent

| Point | Règle | Conséquence d'un écart |
|---|---|---|
| Normalisation du mot de passe | `NFKD` | Les accents composés produisent une clé différente selon l'OS |
| Normalisation de l'e-mail | `trim()` puis `toLowerCase()` | Sel différent, coffre illisible |
| Sel Argon2id | `SHA-256(e-mail)` | Coffre illisible |
| HKDF | Expand **seul**, pas d'Extract | Clé étirée différente, coffre illisible |

⚠ **Validation des paramètres KDF.** Les paramètres arrivent de
`/api/accounts/prelogin`, donc **avant authentification** : entrée non fiable.
Un serveur hostile répondant `iterations: 1` obtient une clé maître dérivée en
un seul tour, et le hash d'authentification transmis suffit alors à casser le
mot de passe hors ligne en quelques secondes.

Le contrôle est borné **dans les deux sens** :

- **Planchers** — en dessous, la clé devient cassable hors ligne. Refus sous
  100 000 itérations PBKDF2 (ancien défaut Bitwarden, conservé pour ne pas
  bloquer les coffres existants) et sous `t=2, m=16 MiB, p=1` pour Argon2id.
- **Plafonds** — au-dessus, c'est un déni de service : `iterations: 2³¹` gèle le
  client, une mémoire Argon2 de plusieurs gibioctets tue l'onglet en OOM au
  déverrouillage. Refus au-dessus de 5 000 000 itérations PBKDF2 et de
  `t=10, m=1024 MiB, p=16` pour Argon2id — les maxima de l'interface du client
  officiel, donc aucun coffre légitime ne peut les dépasser.
- **Valeurs non entières** — `NaN`, flottants et chaînes déguisées en nombres
  sont rejetés avant d'atteindre le KDF (`Number.isSafeInteger`).

**Le client Bitwarden officiel n'effectue aucun de ces contrôles.**

---

## 4. Étirement : 32 → 64 octets

La clé maître fait 32 octets : de quoi chiffrer, pas d'authentifier.

```
encKey = HKDF-Expand-SHA256(prk = clé maître, info = "enc", L = 32)
macKey = HKDF-Expand-SHA256(prk = clé maître, info = "mac", L = 32)

clé maître étirée = encKey ‖ macKey
```

L'étape Extract de HKDF est omise : la clé maître est déjà une PRK uniformément
aléatoire issue du KDF, Extract n'y ajouterait aucune entropie. C'est le choix
de Bitwarden ; s'en écarter rendrait les coffres illisibles.

Les étiquettes `enc` et `mac` garantissent l'indépendance des deux moitiés.
Réutiliser une même clé pour AES et HMAC est une faute classique : la
composition perd toute garantie prouvée.

---

## 5. Hash du mot de passe maître

```
hash = base64( PBKDF2-SHA256(password = clé maître, salt = NFKD(mot de passe), c = usage, dkLen = 32) )
```

PBKDF2 est appliqué « à l'envers » : la clé maître est le mot de passe, le mot
de passe est le sel. Le serveur reçoit une valeur d'où il ne peut retrouver ni
l'un ni l'autre.

| Usage | `c` | Destination |
|---|---|---|
| `ServerAuthorization` | 1 | Envoyé à `/identity/connect/token` |
| `LocalAuthorization` | 2 | Conservé localement pour valider le mot de passe hors ligne |

Le nombre d'itérations **est** la valeur de l'énumération. Les deux hashs sont
donc structurellement distincts : celui stocké localement ne peut pas être
rejoué comme preuve d'authentification, et inversement.

La validation hors ligne passe par `verifyLocalPasswordHash`, qui compare les
**octets décodés** à temps constant — jamais un `===` sur les chaînes base64,
qui court-circuite au premier caractère divergent.

---

## 6. Chiffrement des données

### Construction

```
iv  ← 16 octets aléatoires
ct  ← AES-256-CBC-PKCS7(encKey, iv, clair)
mac ← HMAC-SHA256(macKey, iv ‖ ct)
```

Sérialisation : `2.<base64(iv)>|<base64(ct)>|<base64(mac)>`

### Déchiffrement

```
1. vérifier  HMAC-SHA256(macKey, iv ‖ ct) == mac    (subtle.verify, temps constant natif)
2. si échec  → rejeter, sans toucher AES
3. sinon     → AES-256-CBC-décrypt
```

**L'ordre de ces étapes est la propriété de sécurité la plus importante du
module.** AES-CBC lève une exception sur remplissage PKCS#7 invalide.
Déchiffrer avant de vérifier transforme cette exception en *oracle de padding* :
un attaquant capable de soumettre des ciphertexts et d'observer l'échec
reconstruit le clair bloc par bloc, sans jamais connaître la clé.

Le MAC couvre l'IV **et** le ciphertext. Un IV falsifié permettrait de retourner
des bits arbitraires du premier bloc en clair ; il est donc authentifié.

### Types supportés

| Type | Algorithme | Lecture | Écriture |
|---|---|---|---|
| 0 | AES-256-CBC, sans MAC | legacy ⚠ | refusé |
| 1 | AES-128-CBC + HMAC | refusé | refusé |
| 2 | AES-256-CBC + HMAC-SHA256 | oui | **oui** |
| 3–4 | RSA-2048 OAEP | clés d'organisation uniquement | refusé |
| 5–6 | RSA-2048 OAEP + HMAC | refusé (legacy jamais généralisé) | refusé |

Le RSA ne sert qu'à déballer les **clés d'organisation** (`keyring.ts`) : la
clé privée du compte, elle-même enveloppée par la clé du coffre, déchiffre la
clé de chaque organisation, qui déchiffre ensuite ses items en AES type 2.

---

## 7. Durcissements par rapport au client officiel

### ⚠ Refus de rétrogradation

Une donnée de type 2 resservie comme type 0 est rejetée.

Sans ce contrôle, l'attaque est immédiate : le serveur retire le segment MAC,
change le préfixe `2.` en `0.`, et le client déchiffre sans vérification. L'oracle
de padding neutralisé au §6 est intégralement rouvert.

Implémentation : le déchiffrement d'un type 0 avec une clé authentifiée (64 o)
lève `UnsupportedEncryptionError`. Un vrai coffre legacy utilise une clé de
32 octets, la distinction est donc nette.

### ⚠ Écriture toujours authentifiée

`encryptBytes` lève si la clé ne comporte pas de `macKey`. Zwarden ne peut pas
produire de donnée non authentifiée, quelle que soit la configuration du coffre.

### ⚠ Validation des paramètres KDF

Voir §3.

### ⚠ AES-128 (type 1) refusé en lecture

Format obsolète. Le coffre doit être ré-chiffré. Aucun coffre actif connu ne
l'utilise encore.

---

## 8. Choix d'implémentation

### WebCrypto plutôt qu'un SDK compilé

| Opération | Implémentation | Bundle |
|---|---|---|
| AES-256-CBC | WebCrypto natif | 0 o |
| HMAC-SHA256 | WebCrypto natif | 0 o |
| SHA-256 | WebCrypto natif | 0 o |
| PBKDF2-SHA256 | WebCrypto natif | 0 o |
| HKDF-Expand | boucle de HMAC natifs | ~15 lignes |
| Argon2id | WASM, import dynamique | ~45 Ko, chargé à la demande |

Le client officiel charge 7,4 Mo de SDK Rust au démarrage, inconditionnellement.
Le code natif du navigateur est écrit en C++ à temps constant, audité en continu,
et déjà en mémoire.

Un compte configuré en PBKDF2 ne télécharge **jamais** le module Argon2id.

### base64 délégué à la plateforme

Le chemin principal utilise `Uint8Array.prototype.toBase64` /
`Uint8Array.fromBase64` (proposition TC39 arraybuffer-base64), détectés au
chargement du module ; à défaut, repli sur `btoa`/`atob`. Une implémentation
manuelle a été écrite puis retirée : `scripts/bench-base64.mjs` la mesure
**plus lente** que `atob`/`btoa` (2,2× au décodage), elles-mêmes battues par les
méthodes natives dédiées. 40 lignes de code sensible supprimées pour un gain de
performance.

Les décodeurs de la plateforme **rejettent** les entrées invalides, là où
l'implémentation manuelle les ignorait. C'est le bon comportement : sur du
matériel cryptographique, ignorer des octets illisibles masquerait une
corruption ou une réponse falsifiée. `EncString.parse` traduit ces échecs en
`EncStringParseError`.

### Réutilisation des clés importées

`subtle.importKey` coûte un aller-retour asynchrone vers le module crypto.
`SymmetricCryptoKey` importe donc chaque moitié de clé **une seule fois**
(handles non extractibles, mis en cache paresseusement) : la synchronisation
d'un coffre de N items économise 2 N imports. `destroy()` abandonne les handles
en même temps qu'il efface le matériel brut.

### Comparaison à temps constant

La vérification de MAC est déléguée à `subtle.verify` : code natif, à temps
constant garanti par la plateforme. Une boucle JavaScript « à temps constant »
reste à la merci du JIT, qui ne promet rien sur le profil temporel du code
qu'il optimise.

`timingSafeEqual` demeure pour les comparaisons hors WebCrypto (hash local,
tests). Il parcourt systématiquement toute la longueur et accumule les
différences par OU binaire : une comparaison à court-circuit révèle par son
temps de réponse le nombre d'octets de tête corrects, ce qui ramène la forge
d'un MAC de 2²⁵⁶ à environ 256 × 32 essais.

### Effacement mémoire

`wipe()` et `SymmetricCryptoKey.destroy()` sont **best-effort**. Un moteur JS à
GC générationnel recopie les objets lors des promotions mémoire, et ces copies
sont inatteignables depuis JavaScript. Cela réduit la fenêtre d'exposition aux
dumps mémoire et à l'hibernation, sans la supprimer. Ne pas surestimer cette
garantie.

---

## 9. Couverture de tests

`npm test` — 190 tests unitaires.

| Fichier | Portée |
|---|---|
| `encoding.test.ts` | Vecteurs RFC 4648, sur le chemin natif **et** le repli ; aller-retour sur les 256 valeurs d'octet ; UTF-8 multi-octets ; base64url ; temps constant |
| `primitives.test.ts` | Vecteurs RFC 4231 (HMAC), RFC 7914 (PBKDF2), RFC 5869 (HKDF) ; `subtle.verify` ; équivalence clé brute / `CryptoKey` importée |
| `cryptoService.test.ts` | Aller-retours ; unicité de l'IV ; **altération IV / ciphertext / MAC** ; rétrogradation ; mauvaise clé ; validation structurelle du ciphertext ; vecteur de non-régression figé |
| `kdf.test.ts` | Déterminisme ; normalisation e-mail et mot de passe ; séparation des sels ; refus des KDF faibles, aberrants et non entiers ; séparation des hashs ; validation locale à temps constant |
| `apiClient.test.ts` | `fetch` simulé : validation d'URL, casse des champs, 429 / Retry-After, second facteur, captcha, rafraîchissement de session, 200 non-JSON, jeton absent, idempotence de la suppression ; seul le hash d'autorisation transite |
| `vault.test.ts` | Serveur simulé qui **vérifie le hash** : `unlock()` de bout en bout, refus de KDF faible avant tout envoi, clé enveloppée absente ou falsifiée ; items à clé propre, casse PascalCase, champs corrompus isolés, liste à concurrence bornée |

Les tests d'altération sont les plus importants : ils vérifient que chaque
falsification possible produit bien `MacMismatchError`.

---

## 10. Interopérabilité : validée

L'interopérabilité n'est plus une déduction depuis la spécification, c'est un
fait observé. Validation menée contre **Vaultwarden 2026.6.0**, compte en
PBKDF2-SHA256 à 600 000 itérations.

| Étape | Résultat | Ce que cela prouve |
|---|---|---|
| `prelogin` | PBKDF2, 600 000 itérations | Lecture correcte des paramètres KDF |
| Dérivation de la clé maître | 32 octets | — |
| `connect/token` | **Accepté** | Le hash d'autorisation est identique à celui du client officiel, donc la dérivation de clé maître l'est aussi (NFKD, normalisation e-mail, sel, itérations) |
| Déchiffrement de la clé de coffre | 64 o, MAC vérifié | HKDF-Expand sans Extract, étiquettes `enc`/`mac`, ordre de concaténation, format `EncString` type 2, AES-256-CBC et HMAC-SHA256 : tous corrects |
| Écriture puis relecture | Valeurs identiques | Le chemin de chiffrement produit des données que le serveur accepte et que l'on redéchiffre après un aller-retour complet |

Le test d'écriture est le plus concluant : un item est chiffré localement,
poussé via `POST /api/ciphers`, relu par une synchronisation complète, puis
redéchiffré. Nom, identifiant et mot de passe sont comparés à l'original. L'item
est supprimé en fin de test, y compris en cas d'échec d'assertion.

### Rejouer la validation

```bash
export ZWARDEN_TEST_SERVER=https://vault.exemple.fr
export ZWARDEN_TEST_EMAIL=compte+test@exemple.fr
export ZWARDEN_TEST_PASSWORD='...'
npx vitest run tests/integration
```

Sans ces variables, le test est ignoré : la suite reste exécutable hors ligne.

**Utiliser un compte jetable.** Le test crée et supprime un item. Aucun secret
n'est écrit sur disque ni journalisé — le rapport ne montre que des longueurs et
des identifiants d'items.

### Non encore couvert

- Argon2id contre un vrai serveur (testé unitairement, pas en interopérabilité)
- Items à clé propre (`cipher.key`) — le code les gère, aucun échantillon réel
  rencontré
- Coffres d'organisation contre un vrai serveur — la chaîne RSA complète est
  validée unitairement (paire RSA simulée, profil reconstitué), pas encore en
  interopérabilité
- Pièces jointes
