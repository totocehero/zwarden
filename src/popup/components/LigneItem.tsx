/**
 * @file Une ligne du coffre.
 *
 * Purement présentationnel : la ligne reçoit un item déjà déchiffré et des
 * indicateurs booléens, et remonte des gestes. Elle ne sait ni déchiffrer, ni
 * copier, ni ce qu'est une garde `reprompt` — c'est `App` qui décide si un
 * geste aboutit.
 *
 * C'est aussi ce qui permet au code à usage unique de battre à la seconde sans
 * réafficher la popup entière : {@link CodeOtp} possède son propre état, et la
 * ligne ne lui transmet que des paramètres stables.
 */

import type { CipherOverview } from '@core/vault/cipherService.js';
import type { VaultLabels } from '@core/vault/labels.js';
import type { TotpConfig } from '@core/vault/totp.js';

import { CodeOtp } from './CodeOtp.js';
import { IconCopie, IconCrayon, IconOeil, IconOtp } from './Icons.js';

/** Tag affichable sur un item : dossier ou collection. */
export interface Chip {
  readonly kind: 'dossier' | 'collection';
  readonly name: string;
  readonly title: string;
}

/** Tags d'un item, noms résolus via les étiquettes du coffre. */
export function chipsFor(item: CipherOverview, labels: VaultLabels): Chip[] {
  const chips: Chip[] = [];
  if (item.folderId !== null) {
    const name = labels.folders.get(item.folderId);
    if (name !== undefined) {
      chips.push({ kind: 'dossier', name, title: `Dossier : ${name}` });
    }
  }
  for (const collectionId of item.collectionIds) {
    const collection = labels.collections.get(collectionId);
    if (collection !== undefined) {
      const org =
        collection.organizationId !== null
          ? labels.organizations.get(collection.organizationId)
          : undefined;
      chips.push({
        kind: 'collection',
        name: collection.name,
        title: `${org ?? 'Organisation'} — collection${collection.readOnly ? ' (lecture seule)' : ''}`,
      });
    }
  }
  return chips;
}

export function LigneItem({
  item,
  labels,
  copiePassword,
  copieUsername,
  revele,
  otpConfig,
  copieOtp,
  remplissable,
  onCopyUsername,
  onCopyPassword,
  onToggleReveal,
  onToggleOtp,
  onEdit,
  onFill,
  onCopyOtp,
  onFilter,
}: {
  item: CipherOverview;
  labels: VaultLabels;
  copiePassword: boolean;
  copieUsername: boolean;
  /** Mot de passe révélé, ou `null` s'il est masqué. */
  revele: string | null;
  /** Paramètres du code à usage unique ouvert, ou `null` s'il est fermé. */
  otpConfig: TotpConfig | null;
  copieOtp: boolean;
  /** Vrai si l'origine de l'onglet actif correspond : conditionne « Remplir ». */
  remplissable: boolean;
  onCopyUsername: () => void;
  onCopyPassword: () => void;
  onToggleReveal: () => void;
  onToggleOtp: () => void;
  onEdit: () => void;
  onFill: () => void;
  onCopyOtp: (code: string) => void;
  onFilter: (needle: string) => void;
}) {
  // Calculé une fois : l'appel était fait deux fois par ligne et par
  // réaffichage, une pour tester la présence et une pour rendre.
  const chips = chipsFor(item, labels);

  return (
    <li>
      <div class="item-ligne">
        <div class="item-texte">
          <div class="item-nom" title={item.name ?? ''}>
            {item.name ?? '(sans nom)'}
            {item.hasPasskey && <span class="badge">passkey</span>}
          </div>
          {item.username !== null && (
            <div
              class="item-user"
              title={`Copier : ${item.username}`}
              onClick={onCopyUsername}
            >
              {item.username}
              {copieUsername ? ' — copié !' : ''}
            </div>
          )}
          {item.uris[0] !== undefined && <div class="item-uri">{item.uris[0]}</div>}
          {chips.length > 0 && (
            <div class="chips">
              {chips.map((chip) => (
                <button
                  key={`${chip.kind}:${chip.name}`}
                  class={`chip chip-${chip.kind}`}
                  title={`${chip.title} — cliquer pour filtrer`}
                  onClick={() => onFilter(chip.name)}
                >
                  {chip.kind === 'dossier' ? `#${chip.name}` : `@${chip.name}`}
                </button>
              ))}
            </div>
          )}
        </div>
        {item.hasTotp && (
          <button
            class="discret oeil-item"
            title={
              otpConfig !== null ? 'Masquer le code' : 'Code à usage unique — l’affiche et le copie'
            }
            onClick={onToggleOtp}
          >
            <IconOtp />
          </button>
        )}
        <button
          class="discret oeil-item"
          title={revele !== null ? 'Masquer le mot de passe' : 'Voir le mot de passe'}
          onClick={onToggleReveal}
        >
          <IconOeil barre={revele !== null} />
        </button>
        <button class="discret oeil-item" title="Modifier l’item" onClick={onEdit}>
          <IconCrayon />
        </button>
        <button
          class={`icone${copiePassword ? ' copie-ok' : ''}`}
          title={copiePassword ? 'Mot de passe copié !' : 'Copier le mot de passe'}
          onClick={onCopyPassword}
        >
          <IconCopie fait={copiePassword} />
        </button>
        {remplissable && (
          <button class="remplir" title="Remplir le formulaire de l’onglet actif" onClick={onFill}>
            Remplir
          </button>
        )}
      </div>
      {revele !== null && <div class="secret">{revele}</div>}
      {otpConfig !== null && (
        <CodeOtp config={otpConfig} copie={copieOtp} onCopy={onCopyOtp} />
      )}
    </li>
  );
}
