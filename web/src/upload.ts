/**
 * The upload page.
 *
 * Files are read with a FileReader and parsed by {@link extractLeaves} in
 * this tab. Only the extracted public certificate is sent to the server: the
 * file bytes and any password the user types stay here and are dropped as
 * soon as extraction finishes.
 */

import {
  ExtractionError,
  PasswordRequiredError,
  detectKind,
  extractLeaves,
  type CertificateSummary,
} from "./extract";

const CSRF_COOKIE = "notafter_csrf";
const CSRF_HEADER = "X-CSRF-Token";

interface RegisterResponse {
  readonly id: number;
  readonly created: boolean;
  readonly url: string;
}

interface ServerError {
  readonly code?: string;
  readonly message?: string;
}

function readCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match?.[1] ? decodeURIComponent(match[1]) : "";
}

function formatDate(value: Date): string {
  return `${value.getUTCDate()} ${value.toLocaleString("en-GB", {
    month: "long",
    timeZone: "UTC",
  })} ${value.getUTCFullYear()}`;
}

function groupFingerprint(value: string): string {
  return (value.match(/.{2}/g) ?? []).join(":").toUpperCase();
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** State of one enhanced form. */
class UploadForm {
  private readonly form: HTMLFormElement;
  private readonly fileInput: HTMLInputElement;
  private readonly preview: HTMLElement;
  private readonly jsonUrl: string;
  private candidates: CertificateSummary[] = [];
  private chosen: CertificateSummary | null = null;
  private busy = false;

  constructor(form: HTMLFormElement) {
    this.form = form;
    const file = form.querySelector<HTMLInputElement>("[data-cert-file]");
    const preview = form.querySelector<HTMLElement>("[data-preview]");
    if (!file || !preview) throw new Error("upload form is missing its parts");
    this.fileInput = file;
    this.preview = preview;
    this.jsonUrl = form.dataset["jsonUrl"] ?? "";

    this.fileInput.addEventListener("change", () => {
      void this.handleFile();
    });
    this.form.addEventListener("submit", (event) => {
      if (!this.chosen) return; // fall back to the plain file POST
      event.preventDefault();
      void this.submit();
    });
  }

  private status(message: string, className = "spinner"): void {
    this.preview.hidden = false;
    this.preview.replaceChildren(element("p", className, message));
  }

  private async handleFile(): Promise<void> {
    this.chosen = null;
    this.candidates = [];
    const file = this.fileInput.files?.[0];
    if (!file) {
      this.preview.hidden = true;
      return;
    }

    this.status(`Reading ${file.name} in this browser…`);
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
    } catch {
      this.status("That file could not be read. Try choosing it again.", "error-text");
      return;
    }

    const kind = detectKind(bytes);
    try {
      this.candidates = await extractLeaves(bytes, "");
    } catch (error) {
      if (error instanceof PasswordRequiredError && kind === "pkcs12") {
        // Keep the bytes: askForPassword needs them for the next attempt,
        // and clears them itself once the certificate has been read.
        this.askForPassword(bytes);
        return;
      }
      bytes.fill(0);
      this.showError(error);
      return;
    }
    bytes.fill(0);
    this.showCandidates();
  }

  /** Ask for the .pfx password, in the page. It is never sent anywhere. */
  private askForPassword(bytes: Uint8Array): void {
    this.preview.hidden = false;
    const wrapper = element("div");
    wrapper.append(
      element("h3", undefined, "This file needs its password"),
      element(
        "p",
        "reassurance",
        "The password is used here, in this browser, to read the certificate " +
          "out of the file. It is never sent to the server and is forgotten " +
          "as soon as the certificate has been read.",
      ),
    );

    const field = element("div", "field");
    const label = element("label", undefined, "Password for this file");
    const input = element("input");
    input.type = "password";
    input.autocomplete = "off";
    const id = `pfx-password-${Math.random().toString(36).slice(2, 8)}`;
    input.id = id;
    label.htmlFor = id;
    field.append(label, input);

    const button = element("button", "secondary", "Read the certificate");
    button.type = "button";
    const problem = element("p", "error-text");
    problem.hidden = true;

    const attempt = async (): Promise<void> => {
      problem.hidden = true;
      button.disabled = true;
      try {
        this.candidates = await extractLeaves(bytes, input.value);
            input.value = "";
        bytes.fill(0);
        this.showCandidates();
      } catch (error) {
        button.disabled = false;
        problem.hidden = false;
        problem.textContent =
          error instanceof PasswordRequiredError
            ? "That password did not open the file. Check it and try again."
            : describe(error);
      }
    };

    button.addEventListener("click", () => void attempt());
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        void attempt();
      }
    });

    wrapper.append(field, button, problem);
    this.preview.replaceChildren(wrapper);
    input.focus();
  }

  private showCandidates(): void {
    if (this.candidates.length === 0) {
      this.status("No certificate was found in that file.", "error-text");
      return;
    }
    if (this.candidates.length === 1) {
      const only = this.candidates[0];
      if (only) {
        this.chosen = only;
        this.showPreview(only);
      }
      return;
    }

    this.preview.hidden = false;
    const wrapper = element("div");
    wrapper.append(
      element("h3", undefined, "Which certificate should be tracked?"),
      element(
        "p",
        "reassurance",
        "That file holds more than one certificate. Choose the one whose " +
          "expiry date you want on the board.",
      ),
    );
    const list = element("div", "choices");
    this.candidates.forEach((candidate, index) => {
      const row = element("div", "checkbox");
      const input = element("input");
      input.type = "radio";
      input.name = "leaf-choice";
      input.id = `leaf-${index}`;
      const label = element("label");
      label.htmlFor = input.id;
      label.textContent = `${candidate.commonName || "no common name"} — expires ${formatDate(
        candidate.notAfter,
      )}`;
      input.addEventListener("change", () => {
        this.chosen = candidate;
        this.showPreview(candidate);
      });
      row.append(input, label);
      list.append(row);
    });
    wrapper.append(list);
    this.preview.replaceChildren(wrapper);
  }

  private showPreview(summary: CertificateSummary): void {
    this.preview.hidden = false;
    const wrapper = element("div");
    wrapper.append(element("h3", undefined, "What will be saved"));

    const facts = element("dl", "facts");
    const rows: [string, string][] = [
      ["Common name", summary.commonName || "not present"],
      ["Issued by", summary.issuer],
      ["Valid from", formatDate(summary.notBefore)],
      ["Valid until", formatDate(summary.notAfter)],
      ["SHA-256 fingerprint", groupFingerprint(summary.fingerprintSha256)],
    ];
    for (const [name, value] of rows) {
      facts.append(element("dt", undefined, name), element("dd", "mono", value));
    }
    wrapper.append(facts);
    wrapper.append(
      element(
        "p",
        "reassurance",
        "Only the public certificate will be saved. The private key and " +
          "password stay on your computer.",
      ),
    );
    this.preview.replaceChildren(wrapper);

    const labelField = this.form.querySelector<HTMLInputElement>('input[name="label"]');
    if (labelField && !labelField.value && summary.commonName) {
      labelField.value = summary.commonName;
    }
  }

  private async submit(): Promise<void> {
    if (!this.chosen || this.busy) return;
    this.busy = true;
    const data = new FormData(this.form);
    const confirmBox = this.form.querySelector<HTMLInputElement>("[data-confirm-replacement]");
    const payload = {
      label: String(data.get("label") ?? ""),
      environment: String(data.get("environment") ?? ""),
      owner_email: String(data.get("owner_email") ?? ""),
      notes: String(data.get("notes") ?? ""),
      pem: this.chosen.pem,
      confirm_replacement: Boolean(confirmBox?.checked),
    };

    try {
      const response = await fetch(this.jsonUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          [CSRF_HEADER]: readCookie(CSRF_COOKIE),
        },
        body: JSON.stringify(payload),
        credentials: "same-origin",
      });
      const body = (await response.json()) as RegisterResponse & ServerError;
      if (!response.ok) {
        this.status(body.message ?? "The server refused that certificate.", "error-text");
        this.busy = false;
        return;
      }
      window.location.assign(body.url);
    } catch {
      this.status(
        "The certificate could not be sent. Check your connection and try again.",
        "error-text",
      );
      this.busy = false;
    }
  }

  private showError(error: unknown): void {
    this.status(describe(error), "error-text");
  }
}

function describe(error: unknown): string {
  if (error instanceof ExtractionError || error instanceof PasswordRequiredError) {
    return error.message;
  }
  return "That file could not be read as a certificate. Check that you picked the right one.";
}

/** Turn the stacked sections on the register page into tabs. */
function enhanceTabs(): void {
  const tabs = document.querySelector<HTMLElement>("[data-tabs]");
  if (!tabs) return;
  const buttons = Array.from(tabs.querySelectorAll<HTMLButtonElement>("[data-tab]"));
  const panels = Array.from(document.querySelectorAll<HTMLElement>("[data-panel]"));
  if (buttons.length === 0 || panels.length === 0) return;

  const show = (name: string): void => {
    for (const button of buttons) {
      button.setAttribute("aria-selected", String(button.dataset["tab"] === name));
    }
    for (const panel of panels) {
      panel.hidden = panel.dataset["panel"] !== name;
    }
  };

  for (const button of buttons) {
    button.addEventListener("click", () => show(button.dataset["tab"] ?? ""));
  }
  tabs.hidden = false;
  for (const panel of panels) {
    const heading = panel.querySelector("h3");
    if (heading) heading.hidden = true;
  }
  show(buttons[0]?.dataset["tab"] ?? "");
}

function start(): void {
  enhanceTabs();
  for (const form of document.querySelectorAll<HTMLFormElement>("[data-upload-form]")) {
    try {
      new UploadForm(form);
    } catch {
      // Leave the plain file POST in place if the markup is not what we expect.
    }
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start);
} else {
  start();
}
