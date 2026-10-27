import {
  createEncryptedVault,
  encryptVaultData,
  parseVaultFile,
  serializeVaultFile,
  unlockVault
} from './crypto.js';
import {
  createEncryptedVaultRecord,
  loadEncryptedVault,
  saveEncryptedVault
} from './storage.js';

const $ = selector => document.querySelector(selector);
const inactivityLimit = 2 * 60 * 1000;

const lockScreen = $('#lock-screen');
const dashboardScreen = $('#dashboard-screen');
const unlockForm = $('#unlock-form');
const masterPasswordInput = $('#master-password');
const lockMessage = $('#lock-message');
const unlockButton = $('#unlock-button');
const createVaultButton = $('#create-vault-button');
const importFileInput = $('#import-vault-file');
const accountList = $('#account-list');
const emptyState = $('#empty-state');
const accountSearch = $('#account-search');
const accountDialog = $('#account-dialog');
const accountForm = $('#account-form');
const accountFormMessage = $('#account-form-message');
const toastElement = $('#toast');

let savedEnvelope = null;
let importCandidate = null;
let activeEnvelope = null;
let activeKey = null;
let vaultData = null;
let unlocked = false;
let mode = 'unlock';
let busy = false;
let inactivityTimer = 0;
let toastTimer = 0;
let sessionEpoch = 0;
let editingAccountId = null;
const visiblePasswords = new Set();

masterPasswordInput.autocomplete = 'off';

function setMessage(element, message, kind = '') {
  element.textContent = message;
  element.className = `form-message${kind ? ` ${kind}` : ''}`;
}

function setLockMessage(message, kind = '') {
  setMessage(lockMessage, message, kind);
}

function showToast(message) {
  toastElement.textContent = message;
  toastElement.classList.add('visible');
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => toastElement.classList.remove('visible'), 1900);
}

function createConfirmField() {
  let wrapper = $('#master-confirm-wrapper');
  if (wrapper) return wrapper;

  wrapper = document.createElement('div');
  wrapper.id = 'master-confirm-wrapper';
  wrapper.hidden = true;
  const label = document.createElement('label');
  label.htmlFor = 'master-password-confirm';
  label.textContent = 'Confirm master password';
  const inputWrap = document.createElement('div');
  inputWrap.className = 'input-with-action';
  const input = document.createElement('input');
  input.id = 'master-password-confirm';
  input.type = 'password';
  input.autocomplete = 'new-password';
  input.maxLength = 1024;
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'icon-button';
  toggle.setAttribute('aria-label', 'Show confirmation password');
  toggle.setAttribute('aria-pressed', 'false');
  toggle.textContent = '◉';
  toggle.addEventListener('click', () => togglePasswordVisibility(input, toggle, 'Show confirmation password', 'Hide confirmation password'));
  inputWrap.append(input, toggle);
  wrapper.append(label, inputWrap);
  unlockButton.before(wrapper);
  return wrapper;
}

function confirmInput() { return $('#master-password-confirm'); }

function setMode(nextMode, message = '') {
  mode = nextMode;
  const confirmWrapper = createConfirmField();
  const isCreate = mode === 'create';
  confirmWrapper.hidden = !isCreate;
  createVaultButton.hidden = isCreate && !savedEnvelope;
  $('#master-password-label').textContent = isCreate ? 'Create master password' : 'Master password';
  masterPasswordInput.autocomplete = isCreate ? 'new-password' : 'off';
  unlockButton.textContent = isCreate ? 'Create and unlock vault' : 'Unlock vault';
  createVaultButton.textContent = isCreate ? 'Cancel and return to unlock' : 'Create a new vault';
  masterPasswordInput.value = '';
  if (confirmInput()) confirmInput().value = '';
  setLockMessage(message || (isCreate
    ? 'Use a unique passphrase of at least 12 characters. VaultX cannot recover a forgotten master password.'
    : importCandidate
      ? 'Encrypted vault selected. Enter its master password to verify and import it.'
      : savedEnvelope
        ? 'Your encrypted vault is stored in this browser.'
        : 'No vault is stored in this browser yet. Create one or import an encrypted backup.'));
}

function togglePasswordVisibility(input, button, showLabel, hideLabel) {
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  button.setAttribute('aria-pressed', String(show));
  button.setAttribute('aria-label', show ? hideLabel : showLabel);
}

$('#toggle-master-password').addEventListener('click', () => {
  togglePasswordVisibility(masterPasswordInput, $('#toggle-master-password'), 'Show master password', 'Hide master password');
});
$('#toggle-account-password').addEventListener('click', () => {
  togglePasswordVisibility($('#account-password'), $('#toggle-account-password'), 'Show password', 'Hide password');
});

function requireActiveVault() {
  if (!unlocked || !vaultData || !activeEnvelope || !activeKey) throw new Error('Unlock the vault again before making changes.');
}

function randomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function randomIndex(length) {
  if (!Number.isInteger(length) || length < 1 || length > 256) throw new Error('Invalid password generator setting.');
  const limit = Math.floor(256 / length) * length;
  const sample = new Uint8Array(1);
  do { crypto.getRandomValues(sample); } while (sample[0] >= limit);
  return sample[0] % length;
}

function generateSecurePassword(length, useUpper, useLower, useNumbers, useSymbols) {
  const groups = [];
  if (useUpper) groups.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (useLower) groups.push('abcdefghijkmnopqrstuvwxyz');
  if (useNumbers) groups.push('23456789');
  if (useSymbols) groups.push('!@#$%^&*()-_=+[]{}:,.?');
  if (groups.length === 0) throw new Error('Select at least one character type.');
  if (!Number.isInteger(length) || length < groups.length || length > 64) {
    throw new Error(`Choose a length from ${groups.length} to 64 for the selected character types.`);
  }

  const alphabet = groups.join('');
  const output = groups.map(group => group[randomIndex(group.length)]);
  while (output.length < length) output.push(alphabet[randomIndex(alphabet.length)]);
  for (let index = output.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1);
    [output[index], output[swapIndex]] = [output[swapIndex], output[index]];
  }
  return output.join('');
}

let generatorDialog;
function buildGeneratorDialog() {
  const dialog = document.createElement('dialog');
  dialog.className = 'account-dialog generator-dialog';
  dialog.setAttribute('aria-labelledby', 'generator-title');
  const form = document.createElement('form');
  form.method = 'dialog';
  const heading = document.createElement('div');
  heading.className = 'dialog-heading';
  const titleBlock = document.createElement('div');
  const eyebrow = document.createElement('p');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = 'SECURE RANDOMNESS';
  const title = document.createElement('h2');
  title.id = 'generator-title';
  title.textContent = 'Password generator';
  titleBlock.append(eyebrow, title);
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'icon-button close-dialog-button';
  close.setAttribute('aria-label', 'Close password generator');
  close.textContent = '×';
  close.addEventListener('click', () => dialog.close());
  heading.append(titleBlock, close);

  const lengthLabel = document.createElement('label');
  lengthLabel.htmlFor = 'generator-length';
  lengthLabel.textContent = 'Password length';
  const lengthInput = document.createElement('input');
  lengthInput.id = 'generator-length';
  lengthInput.type = 'number';
  lengthInput.min = '8';
  lengthInput.max = '64';
  lengthInput.value = '20';
  lengthInput.inputMode = 'numeric';
  const options = document.createElement('div');
  options.className = 'generator-options';
  const choices = [
    ['generator-uppercase', 'Uppercase letters', true],
    ['generator-lowercase', 'Lowercase letters', true],
    ['generator-numbers', 'Numbers', true],
    ['generator-symbols', 'Special characters', true]
  ];
  for (const [id, text, checked] of choices) {
    const label = document.createElement('label');
    label.className = 'checkbox-option';
    const checkbox = document.createElement('input');
    checkbox.id = id;
    checkbox.type = 'checkbox';
    checkbox.checked = checked;
    label.append(checkbox, document.createTextNode(text));
    options.append(label);
  }
  const resultLabel = document.createElement('label');
  resultLabel.htmlFor = 'generated-password-preview';
  resultLabel.textContent = 'Generated password';
  const preview = document.createElement('input');
  preview.id = 'generated-password-preview';
  preview.type = 'text';
  preview.readOnly = true;
  preview.autocomplete = 'off';
  preview.spellcheck = false;
  const status = document.createElement('p');
  status.className = 'form-message';
  status.setAttribute('role', 'status');
  const actions = document.createElement('div');
  actions.className = 'dialog-actions';
  const refresh = document.createElement('button');
  refresh.type = 'button';
  refresh.className = 'secondary-button';
  refresh.textContent = 'Generate another';
  const useButton = document.createElement('button');
  useButton.type = 'button';
  useButton.className = 'primary-button';
  useButton.textContent = 'Use password';
  actions.append(refresh, useButton);
  form.append(heading, lengthLabel, lengthInput, options, resultLabel, preview, status, actions);
  dialog.append(form);
  document.body.append(dialog);

  function generate() {
    try {
      preview.value = generateSecurePassword(
        Number(lengthInput.value),
        $('#generator-uppercase').checked,
        $('#generator-lowercase').checked,
        $('#generator-numbers').checked,
        $('#generator-symbols').checked
      );
      status.textContent = '';
      status.className = 'form-message';
    } catch (error) {
      preview.value = '';
      status.textContent = error.message;
      status.className = 'form-message error';
    }
  }
  refresh.addEventListener('click', generate);
  useButton.addEventListener('click', () => {
    if (!preview.value) { generate(); if (!preview.value) return; }
    $('#account-password').value = preview.value;
    $('#account-password').type = 'text';
    $('#toggle-account-password').setAttribute('aria-pressed', 'true');
    $('#toggle-account-password').setAttribute('aria-label', 'Hide password');
    dialog.close();
    $('#account-password').focus();
  });
  dialog.addEventListener('close', () => { preview.value = ''; status.textContent = ''; });
  dialog.addEventListener('cancel', () => { preview.value = ''; });
  dialog.showModal();
  generate();
  return dialog;
}

function openGenerator() {
  if (generatorDialog?.open) return;
  if (generatorDialog) generatorDialog.remove();
  generatorDialog = buildGeneratorDialog();
}
$('#generate-password-button').addEventListener('click', openGenerator);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function iconButton(label, symbol, callback, pressed) {
  const button = element('button', 'icon-button', symbol);
  button.type = 'button';
  button.setAttribute('aria-label', label);
  if (pressed !== undefined) button.setAttribute('aria-pressed', String(pressed));
  button.addEventListener('click', callback);
  return button;
}

function allowedWebsite(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url : null;
  } catch { return null; }
}

function accountMatches(account, query) {
  if (!query) return true;
  const haystack = [account.platform, account.username, account.website].join('\n').toLocaleLowerCase();
  return haystack.includes(query);
}

function renderAccount(account) {
  const card = element('article', 'account-card');
  const header = element('div', 'account-card-header');
  const identity = element('div', 'account-identity');
  const glyph = element('div', 'account-glyph', (account.platform || '?').trim().slice(0, 1).toUpperCase());
  glyph.setAttribute('aria-hidden', 'true');
  const titleBlock = document.createElement('div');
  const title = element('h3', '', account.platform);
  title.title = account.platform;
  titleBlock.append(title);
  const site = allowedWebsite(account.website);
  if (site) {
    const siteLink = element('a', 'account-site', site.hostname);
    siteLink.href = site.href;
    siteLink.target = '_blank';
    siteLink.rel = 'noopener noreferrer';
    siteLink.title = site.href;
    titleBlock.append(siteLink);
  }
  identity.append(glyph, titleBlock);
  const menu = element('div', 'account-menu');
  menu.append(iconButton('Edit account', '···', () => beginEdit(account.id)));
  header.append(identity, menu);
  card.append(header);

  const idField = element('div', 'account-field');
  idField.append(element('span', 'account-field-label', 'Account ID / Username'));
  const idRow = element('div', 'account-value-row');
  idRow.append(element('span', 'account-value', account.username || 'Not set'));
  const idActions = element('div', 'value-actions');
  if (account.username) idActions.append(iconButton('Copy account ID', '⧉', () => copySecret(account.username, 'Account ID copied')));
  idRow.append(idActions);
  idField.append(idRow);
  card.append(idField);

  const passwordField = element('div', 'account-field');
  passwordField.append(element('span', 'account-field-label', 'Password'));
  const passwordRow = element('div', 'account-value-row');
  const isVisible = visiblePasswords.has(account.id);
  passwordRow.append(element('span', `account-value${isVisible ? '' : ' masked'}`, isVisible ? account.password : '••••••••••••'));
  const passwordActions = element('div', 'value-actions');
  passwordActions.append(iconButton(isVisible ? 'Hide password' : 'Reveal password', isVisible ? '◉' : '○', () => {
    if (visiblePasswords.has(account.id)) visiblePasswords.delete(account.id);
    else visiblePasswords.add(account.id);
    renderDashboard();
  }, isVisible));
  passwordActions.append(iconButton('Copy password', '⧉', () => copySecret(account.password, 'Password copied')));
  passwordRow.append(passwordActions);
  passwordField.append(passwordRow);
  card.append(passwordField);

  if (account.notes) card.append(element('p', 'account-notes', account.notes));
  const actions = element('div', 'card-actions');
  const editButton = element('button', 'secondary-button', 'Edit');
  editButton.type = 'button';
  editButton.addEventListener('click', () => beginEdit(account.id));
  const deleteButton = element('button', 'secondary-button delete-button', 'Delete');
  deleteButton.type = 'button';
  deleteButton.addEventListener('click', () => deleteAccount(account.id));
  actions.append(editButton, deleteButton);
  card.append(actions);
  return card;
}

function renderDashboard() {
  if (!unlocked || !vaultData) return;
  const query = accountSearch.value.trim().toLocaleLowerCase();
  const matches = vaultData.accounts.filter(account => accountMatches(account, query));
  accountList.replaceChildren(...matches.map(renderAccount));
  emptyState.hidden = vaultData.accounts.length > 0;
  if (vaultData.accounts.length > 0 && matches.length === 0) {
    accountList.append(element('p', 'empty-state search-empty', 'No accounts match your search.'));
  }
}

function showDashboard() {
  unlocked = true;
  lockScreen.classList.add('hidden');
  dashboardScreen.classList.remove('hidden');
  dashboardScreen.inert = false;
  accountSearch.value = '';
  renderDashboard();
  startInactivityTimer();
}

function stopTimer() {
  window.clearTimeout(inactivityTimer);
  inactivityTimer = 0;
}

function startInactivityTimer() {
  stopTimer();
  inactivityTimer = window.setTimeout(lockVault, inactivityLimit);
}

function lockVault() {
  sessionEpoch += 1;
  stopTimer();
  if (generatorDialog?.open) generatorDialog.close();
  if (accountDialog.open) accountDialog.close();
  unlocked = false;
  activeKey = null;
  activeEnvelope = null;
  vaultData = null;
  visiblePasswords.clear();
  accountList.replaceChildren();
  accountSearch.value = '';
  accountForm.reset();
  masterPasswordInput.value = '';
  if (confirmInput()) confirmInput().value = '';
  $('#account-password').type = 'password';
  $('#toggle-account-password').setAttribute('aria-pressed', 'false');
  $('#toggle-account-password').setAttribute('aria-label', 'Show password');
  dashboardScreen.classList.add('hidden');
  dashboardScreen.inert = true;
  lockScreen.classList.remove('hidden');
  const nextMode = importCandidate ? 'unlock' : savedEnvelope ? 'unlock' : 'create';
  setMode(nextMode, 'Vault locked. Enter the master password to unlock it again.');
  masterPasswordInput.focus({ preventScroll: true });
}

async function copySecret(value, successMessage) {
  try {
    if (!navigator.clipboard?.writeText || !window.isSecureContext) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(value);
    showToast(successMessage);
  } catch {
    showToast('Copy unavailable. Open VaultX over HTTPS and try again.');
  }
}

async function persistUpdatedVault(nextData) {
  requireActiveVault();
  const token = sessionEpoch;
  const key = activeKey;
  const currentEnvelope = activeEnvelope;
  const nextEnvelope = await encryptVaultData(nextData, key, currentEnvelope);
  if (!unlocked || token !== sessionEpoch) throw new Error('Vault locked during update.');
  await saveEncryptedVault(nextEnvelope);
  if (!unlocked || token !== sessionEpoch) return;
  activeEnvelope = nextEnvelope;
  savedEnvelope = nextEnvelope;
  vaultData = nextData;
}

async function deleteAccount(id) {
  if (busy) return;
  const account = vaultData?.accounts.find(item => item.id === id);
  if (!account) return;
  if (!window.confirm(`Delete the ${account.platform} entry from this vault?`)) return;
  const nextData = { ...vaultData, accounts: vaultData.accounts.filter(item => item.id !== id) };
  busy = true;
  try {
    await persistUpdatedVault(nextData);
    visiblePasswords.delete(id);
    renderDashboard();
    showToast('Account deleted and vault encrypted');
  } catch {
    showToast('Could not save the change. Your saved vault is unchanged.');
  } finally {
    busy = false;
  }
}

function beginEdit(id) {
  const account = vaultData?.accounts.find(item => item.id === id);
  if (!account) return;
  editingAccountId = id;
  $('#account-dialog-title').textContent = 'Edit account';
  $('#save-account-button').textContent = 'Encrypt and save';
  $('#account-id').value = account.id;
  $('#platform').value = account.platform;
  $('#username').value = account.username;
  $('#account-password').value = account.password;
  $('#account-password').type = 'password';
  $('#toggle-account-password').setAttribute('aria-pressed', 'false');
  $('#toggle-account-password').setAttribute('aria-label', 'Show password');
  $('#website-url').value = account.website;
  $('#account-notes').value = account.notes;
  setMessage(accountFormMessage, '');
  accountDialog.showModal();
  $('#platform').focus();
}

function beginAdd() {
  editingAccountId = null;
  accountForm.reset();
  $('#account-id').value = '';
  $('#account-dialog-title').textContent = 'Add account';
  $('#save-account-button').textContent = 'Encrypt and save';
  $('#account-password').type = 'password';
  $('#toggle-account-password').setAttribute('aria-pressed', 'false');
  $('#toggle-account-password').setAttribute('aria-label', 'Show password');
  setMessage(accountFormMessage, '');
  accountDialog.showModal();
  $('#platform').focus();
}

async function saveAccount(event) {
  event.preventDefault();
  if (busy) return;
  const platform = $('#platform').value.trim();
  const username = $('#username').value.trim();
  const password = $('#account-password').value;
  const websiteRaw = $('#website-url').value.trim();
  const notes = $('#account-notes').value.trim();
  if (!platform) { setMessage(accountFormMessage, 'Enter a platform name.', 'error'); return; }
  if (!password) { setMessage(accountFormMessage, 'Enter a password or generate one.', 'error'); return; }
  if (websiteRaw && !allowedWebsite(websiteRaw)) {
    setMessage(accountFormMessage, 'Use a valid website address beginning with http:// or https://.', 'error');
    return;
  }
  if (new TextEncoder().encode(password).length > 1024) {
    setMessage(accountFormMessage, 'The password is too long.', 'error');
    return;
  }
  const now = new Date().toISOString();
  const prior = editingAccountId ? vaultData.accounts.find(item => item.id === editingAccountId) : null;
  const account = {
    id: prior?.id || randomId(),
    platform,
    username,
    password,
    website: websiteRaw ? allowedWebsite(websiteRaw).href : '',
    notes,
    createdAt: prior?.createdAt || now,
    updatedAt: now
  };
  const nextAccounts = prior
    ? vaultData.accounts.map(item => item.id === prior.id ? account : item)
    : [...vaultData.accounts, account];
  const nextData = { ...vaultData, accounts: nextAccounts };

  busy = true;
  $('#save-account-button').disabled = true;
  try {
    await persistUpdatedVault(nextData);
    visiblePasswords.delete(account.id);
    accountDialog.close();
    renderDashboard();
    showToast(prior ? 'Account updated and vault encrypted' : 'Account added and vault encrypted');
  } catch {
    setMessage(accountFormMessage, 'Could not save the encrypted change. Your previously saved vault is unchanged.', 'error');
  } finally {
    busy = false;
    $('#save-account-button').disabled = false;
  }
}

function resetCreateForm() {
  importCandidate = null;
  if (importFileInput) importFileInput.value = '';
  setMode(savedEnvelope ? 'unlock' : 'create');
}

async function handleUnlock(event) {
  event.preventDefault();
  if (busy) return;
  const masterPassword = masterPasswordInput.value;
  if (mode === 'create') {
    if (masterPassword.length < 12) {
      setLockMessage('Choose a master password with at least 12 characters. A longer, unique passphrase is safer.', 'error');
      return;
    }
    if (masterPassword !== confirmInput().value) {
      setLockMessage('The confirmation does not match. Re-enter both fields.', 'error');
      return;
    }
  }
  if (!masterPassword) { setLockMessage('Enter your master password.', 'error'); return; }
  busy = true;
  unlockButton.disabled = true;
  unlockButton.textContent = mode === 'create' ? 'Creating encrypted vault…' : 'Unlocking…';
  try {
    if (mode === 'create') {
      const nextEnvelope = await createEncryptedVault(masterPassword);
      if (savedEnvelope) await saveEncryptedVault(nextEnvelope);
      else await createEncryptedVaultRecord(nextEnvelope);
      savedEnvelope = nextEnvelope;
      importCandidate = null;
      const unlockedResult = await unlockVault(nextEnvelope, masterPassword);
      activeEnvelope = nextEnvelope;
      activeKey = unlockedResult.key;
      vaultData = unlockedResult.data;
    } else {
      const envelope = importCandidate || savedEnvelope;
      if (!envelope) {
        setMode('create');
        return;
      }
      const unlockedResult = await unlockVault(envelope, masterPassword);
      if (importCandidate) {
        await saveEncryptedVault(envelope);
        savedEnvelope = envelope;
        importCandidate = null;
      }
      activeEnvelope = envelope;
      activeKey = unlockedResult.key;
      vaultData = unlockedResult.data;
    }
    setLockMessage('');
    masterPasswordInput.value = '';
    if (confirmInput()) confirmInput().value = '';
    showDashboard();
  } catch (error) {
    setLockMessage(mode === 'create'
      ? 'Could not create the vault. Check browser storage and try again.'
      : (error.message === 'Could not unlock this vault. Check the master password and vault file.'
        ? error.message
        : 'Could not unlock or save this vault. Check the file and available browser storage.'), 'error');
  } finally {
    busy = false;
    unlockButton.disabled = false;
    unlockButton.textContent = mode === 'create' ? 'Create and unlock vault' : 'Unlock vault';
  }
}

unlockForm.addEventListener('submit', handleUnlock);
$('#lock-now-button').addEventListener('click', lockVault);
$('#add-account-button').addEventListener('click', beginAdd);
$('#empty-add-account-button').addEventListener('click', beginAdd);
$('#close-account-dialog').addEventListener('click', () => accountDialog.close());
$('#cancel-account-button').addEventListener('click', () => accountDialog.close());
accountForm.addEventListener('submit', saveAccount);
accountDialog.addEventListener('close', () => { editingAccountId = null; accountForm.reset(); });
accountSearch.addEventListener('input', renderDashboard);
$('#export-vault-button').addEventListener('click', () => {
  if (!unlocked || !activeEnvelope) return;
  const file = new Blob([serializeVaultFile(activeEnvelope)], { type: 'application/json' });
  const objectUrl = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = 'vaultx-backup.vaultx';
  link.rel = 'noopener';
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  showToast('Encrypted backup downloaded');
});

createVaultButton.addEventListener('click', () => {
  if (mode === 'create') {
    resetCreateForm();
    return;
  }
  if (savedEnvelope && !window.confirm('Create a new vault and replace the encrypted vault saved in this browser? Export a backup first if you need to keep its accounts.')) return;
  importCandidate = null;
  setMode('create');
  masterPasswordInput.focus();
});

importFileInput.addEventListener('change', async () => {
  const file = importFileInput.files?.[0];
  if (!file) return;
  if (file.size > 20 * 1024 * 1024) {
    setLockMessage('The selected encrypted vault file is too large.', 'error');
    importFileInput.value = '';
    return;
  }
  try {
    let fileText;
    if (typeof file.text === 'function') fileText = await file.text();
    else {
      fileText = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ''));
        reader.onerror = () => reject(new Error('Could not read the selected encrypted vault file.'));
        reader.readAsText(file);
      });
    }
    importCandidate = parseVaultFile(fileText);
    setMode('unlock', 'Encrypted vault selected. Enter its master password to verify and import it. Your current saved vault will only be replaced after successful unlock.');
    masterPasswordInput.focus();
  } catch (error) {
    importCandidate = null;
    setLockMessage(error.message, 'error');
    importFileInput.value = '';
  }
});

$('#account-password').addEventListener('input', event => {
  if (event.currentTarget.value.length) setMessage(accountFormMessage, '');
});

for (const eventName of ['pointerdown', 'pointermove', 'keydown', 'touchstart', 'wheel']) {
  document.addEventListener(eventName, () => { if (unlocked) startInactivityTimer(); }, { passive: true });
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden' && unlocked) lockVault(); });
window.addEventListener('pagehide', () => { if (unlocked) lockVault(); });

(async function initialize() {
  try {
    savedEnvelope = (await loadEncryptedVault()) || null;
    setMode(savedEnvelope ? 'unlock' : 'create');
  } catch {
    setLockMessage('Browser storage is unavailable. Open VaultX over HTTPS in a modern browser.', 'error');
    unlockButton.disabled = true;
    createVaultButton.disabled = true;
  }
})();
