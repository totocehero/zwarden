/**
 * @file Orchestration du déverrouillage du coffre.
 *
 * ## Pourquoi ce module existe
 *
 * Le déverrouillage complet est une chorégraphie dont l'ordre est critique :
 *
 * ```
 *   prelogin ─► deriveMasterKey ─► derivePasswordHash ─► login
 *                     │                                    │
 *                     ▼                                    ▼
 *              stretchMasterKey ──────► déchiffre `protectedUserKey`
 *                     │                                    │
 *                  destroy()                               ▼
 *                                                   clé du coffre
 * ```
 *
 * avec, en plus, l'hygiène mémoire : la clé maître et la clé étirée doivent
 * être effacées dès qu'elles ont servi — seule la clé du coffre survit. Chaque
 * consommateur (popup, service worker, tests) qui réécrirait cette danse
 * serait une occasion de se tromper sur l'ordre ou d'oublier un effacement.
 * Elle est donc écrite et auditée **une fois**, ici.
 *
 * ## Répartition des couches
 *
 * `core/crypto` fournit les primitives et les clés, `core/api` le transport
 * sans aucun secret, et ce module est le seul à faire circuler les deux.
 */

import { ApiClient, type LoginResult, type TwoFactorSubmission } from '../api/apiClient.js';
import { EncString } from '../crypto/encString.js';
import { decryptBytes } from '../crypto/cryptoService.js';
import {
  HashPurpose,
  type KdfConfig,
  deriveMasterKey,
  derivePasswordHash,
  stretchMasterKey,
} from '../crypto/kdf.js';
import { SymmetricCryptoKey } from '../crypto/symmetricCryptoKey.js';

/** Levée lorsque la réponse du serveur ne permet pas d'ouvrir le coffre. */
export class UnlockError extends Error {
  override readonly name = 'UnlockError';
  /** Identifiant stable pour l'interface : les messages servent aux journaux. */
  readonly code = 'unlock-failed';
}

/** Résultat d'un déverrouillage réussi. */
export interface UnlockResult {
  /** Jetons de session, pour les appels API suivants. */
  readonly session: LoginResult;
  /**
   * Clé du coffre, déchiffrée et authentifiée. À détruire au verrouillage
   * (`userKey.destroy()`), avec purge de tout stockage de session.
   */
  readonly userKey: SymmetricCryptoKey;
  /**
   * Hash local du mot de passe, à conserver pour la validation hors ligne
   * (voir `verifyLocalPasswordHash`). Ne peut pas être rejoué auprès du
   * serveur : son nombre d'itérations diffère du hash d'autorisation.
   */
  readonly localPasswordHash: string;
  /** Paramètres KDF validés, à conserver pour le déverrouillage hors ligne. */
  readonly kdfConfig: KdfConfig;
  /**
   * Jeton de dispense de second facteur, si `remember` a été demandé et
   * accepté. À persister par appareil et rejouer aux prochains
   * déverrouillages (fournisseur 5).
   */
  readonly twoFactorRememberToken: string | undefined;
}

/**
 * Déverrouille le coffre à partir du mot de passe maître.
 *
 * Encapsule la chorégraphie décrite en en-tête. Au retour, la clé maître et
 * la clé étirée ont été effacées ; il ne reste en mémoire que la clé du
 * coffre et les jetons.
 *
 * @param client Client API pointant l'instance de l'utilisateur.
 * @param email E-mail du compte.
 * @param password Mot de passe maître, en clair. N'est transmis nulle part ;
 *   ses formes dérivées sont effacées par les couches inférieures.
 * @param twoFactor Second facteur à joindre — code saisi après un premier
 *   refus, ou jeton de dispense conservé (fournisseur 5).
 * @returns Session, clé du coffre et matériel de validation hors ligne.
 * @throws {WeakKdfError} Paramètres KDF du serveur hors bornes.
 * @throws {TwoFactorRequiredError} Une seconde étape est exigée.
 * @throws {CaptchaRequiredError} Le serveur exige un captcha.
 * @throws {RateLimitedError} Le serveur limite le débit.
 * @throws {ApiError} Identifiants refusés ou autre échec HTTP.
 * @throws {UnlockError} Réponse sans clé de coffre exploitable.
 * @throws {MacMismatchError} Clé de coffre enveloppée illisible — corruption
 *   ou falsification côté serveur.
 */
export async function unlock(
  client: ApiClient,
  email: string,
  password: string,
  twoFactor?: TwoFactorSubmission,
): Promise<UnlockResult> {
  const kdfConfig = await client.prelogin(email);
  const masterKey = await deriveMasterKey(password, email, kdfConfig);

  try {
    // Les deux hashs sont indépendants : calculés de front.
    const [serverHash, localPasswordHash] = await Promise.all([
      derivePasswordHash(masterKey, password, HashPurpose.ServerAuthorization),
      derivePasswordHash(masterKey, password, HashPurpose.LocalAuthorization),
    ]);

    const session = await client.login(email, serverHash, twoFactor);

    if (session.protectedUserKey === undefined) {
      throw new UnlockError(
        "Le serveur n'a pas fourni de clé de coffre enveloppée : compte incomplet ou réponse falsifiée",
      );
    }

    const stretched = await stretchMasterKey(masterKey);
    try {
      const rawUserKey = await decryptBytes(EncString.parse(session.protectedUserKey), stretched);
      return {
        session,
        userKey: new SymmetricCryptoKey(rawUserKey),
        localPasswordHash,
        kdfConfig,
        twoFactorRememberToken: session.twoFactorRememberToken,
      };
    } finally {
      stretched.destroy();
    }
  } finally {
    masterKey.destroy();
  }
}
