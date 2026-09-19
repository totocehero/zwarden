/**
 * @file Règle du verrouillage automatique.
 *
 * Le reste du mécanisme (alarme périodique, événements de navigateur) n'existe
 * que dans un navigateur ; la décision, elle, est une fonction pure — et c'est
 * elle qui décide de redemander le mot de passe maître. Elle est donc la seule
 * partie qu'il vaut la peine d'épingler ici.
 */

import { describe, expect, it } from 'vitest';

import { DEFAULT_SETTINGS, shouldAutoLock } from '../src/shared/storage.js';

const MINUTE = 60_000;

describe('shouldAutoLock', () => {
  it('ne verrouille jamais quand le délai est nul', () => {
    // Le défaut : seule la fermeture du navigateur verrouille.
    expect(DEFAULT_SETTINGS.autoLockMinutes).toBe(0);
    expect(shouldAutoLock(0, 0, 10 * 365 * 24 * 60 * MINUTE)).toBe(false);
  });

  it('ne verrouille pas avant l’échéance', () => {
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 14 * MINUTE)).toBe(false);
  });

  it('verrouille à l’échéance et au-delà', () => {
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 15 * MINUTE)).toBe(true);
    expect(shouldAutoLock(1_000_000, 15, 1_000_000 + 60 * MINUTE)).toBe(true);
  });

  it('ne verrouille pas sur une absence d’horodatage', () => {
    // Un horodatage perdu n'est pas une preuve d'inactivité : le service
    // worker le réinitialise plutôt que de verrouiller.
    expect(shouldAutoLock(null, 15, Date.now())).toBe(false);
  });
});
