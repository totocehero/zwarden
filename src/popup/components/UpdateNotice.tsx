/**
 * @file One line at the top of the vault when a newer release is known.
 *
 * Read from storage, where the last check left it: the popup itself asks
 * nobody anything. Shown only when the version found is newer than the one
 * running and the user has not dismissed that very version — a dismissed 0.2.0
 * says nothing about 0.3.0.
 */

import { t } from '@shared/i18n.js';
import { useEffect, useState } from 'preact/hooks';

import { isNewer, type Release } from '@core/update/updateCheck.js';
import { loadDismissedUpdate, loadUpdateStatus, saveDismissedUpdate } from '@shared/storage.js';

/** The installed version, or `dev` outside an extension (Vite preview). */
function installedVersion(): string {
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.getManifest === 'function') {
    return chrome.runtime.getManifest().version;
  }
  return 'dev';
}

/** The release to announce, or `null` when there is nothing newer or it was dismissed. */
async function pendingRelease(): Promise<Release | null> {
  const [status, dismissed] = await Promise.all([loadUpdateStatus(), loadDismissedUpdate()]);
  const latest = status?.latest ?? null;
  if (latest === null || latest.version === dismissed) {
    return null;
  }
  return isNewer(installedVersion(), latest.version) ? latest : null;
}

export function UpdateNotice({ onOpen }: { onOpen: (url: string) => void }) {
  const [release, setRelease] = useState<Release | null>(null);

  useEffect(() => {
    void pendingRelease().then(setRelease);
  }, []);

  if (release === null) {
    return null;
  }
  return (
    <p class="update-notice">
      {t('updateNoticeAvailable', release.version)}{' '}
      <button class="quiet" onClick={() => onOpen(release.url)}>
        {t('updateNoticeOpen')}
      </button>
      <button
        class="quiet"
        onClick={() => {
          void saveDismissedUpdate(release.version);
          setRelease(null);
        }}
      >
        {t('updateNoticeDismiss')}
      </button>
    </p>
  );
}
