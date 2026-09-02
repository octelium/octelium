const NAMED_KEYS = [
  "Enter",
  "Backspace",
  "Tab",
  "Escape",
  "Delete",
  "ArrowUp",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "Home",
  "End",
  "PageUp",
  "PageDown",
];

const HIDDEN_INPUT_STYLE = [
  "position:absolute",
  "bottom:0",
  "left:0",
  "width:1px",
  "height:1px",
  "padding:0",
  "border:0",
  "opacity:0",
  "font-size:16px",
  "background:transparent",
  "color:transparent",
  "caret-color:transparent",
].join(";");

export type SoftKeyboard = {
  open: () => void;
  close: () => void;
  dispose: () => void;
};

export type SoftKeyboardOpts = {
  onVisibilityChange: (visible: boolean) => void;
};

export function createSoftKeyboard(
  host: HTMLElement,
  opts: SoftKeyboardOpts,
): SoftKeyboard | null {
  const root = host.shadowRoot;
  if (!root) {
    return null;
  }

  const target = root.querySelector<HTMLCanvasElement>("canvas") ?? host;

  const input = document.createElement("input");
  input.type = "text";
  input.autocapitalize = "off";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.setAttribute("aria-hidden", "true");
  input.setAttribute("enterkeyhint", "enter");
  input.style.cssText = HIDDEN_INPUT_STYLE;
  root.appendChild(input);

  const sendKey = (key: string, code: string) => {
    for (const type of ["keydown", "keyup"]) {
      target.dispatchEvent(
        new KeyboardEvent(type, {
          key,
          code,
          bubbles: true,
          composed: true,
          cancelable: true,
        }),
      );
    }
  };

  const onKeyDown = (event: KeyboardEvent) => {
    event.stopPropagation();

    if (NAMED_KEYS.includes(event.key)) {
      event.preventDefault();
      sendKey(event.key, event.key);
    }
  };

  const onKeyUp = (event: KeyboardEvent) => {
    event.stopPropagation();
  };

  const onBeforeInput = (event: InputEvent) => {
    event.preventDefault();

    switch (event.inputType) {
      case "insertText":
      case "insertCompositionText":
        for (const char of event.data ?? "") {
          sendKey(char, "");
        }
        break;
      case "insertLineBreak":
      case "insertParagraph":
        sendKey("Enter", "Enter");
        break;
      case "deleteContentBackward":
        sendKey("Backspace", "Backspace");
        break;
      case "deleteContentForward":
        sendKey("Delete", "Delete");
        break;
    }
  };

  const onInput = () => {
    input.value = "";
  };

  const onFocus = () => opts.onVisibilityChange(true);
  const onBlur = () => opts.onVisibilityChange(false);

  input.addEventListener("keydown", onKeyDown);
  input.addEventListener("keyup", onKeyUp);
  input.addEventListener("beforeinput", onBeforeInput);
  input.addEventListener("input", onInput);
  input.addEventListener("focus", onFocus);
  input.addEventListener("blur", onBlur);

  return {
    open: () => input.focus({ preventScroll: true }),
    close: () => input.blur(),
    dispose: () => {
      input.removeEventListener("keydown", onKeyDown);
      input.removeEventListener("keyup", onKeyUp);
      input.removeEventListener("beforeinput", onBeforeInput);
      input.removeEventListener("input", onInput);
      input.removeEventListener("focus", onFocus);
      input.removeEventListener("blur", onBlur);
      input.remove();
    },
  };
}
