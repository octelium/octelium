const SCROLL_STEP = 24;

type Point = { x: number; y: number };

type TouchMode = "idle" | "drag" | "scroll";

function getCanvas(host: HTMLElement): HTMLCanvasElement | null {
  return host.shadowRoot?.querySelector<HTMLCanvasElement>("canvas") ?? null;
}

function toPoint(touch: Touch): Point {
  return { x: touch.clientX, y: touch.clientY };
}

function midpoint(touches: TouchList): Point {
  return {
    x: (touches[0].clientX + touches[1].clientX) / 2,
    y: (touches[0].clientY + touches[1].clientY) / 2,
  };
}

function sendMouse(
  canvas: HTMLCanvasElement,
  type: string,
  point: Point,
  buttons: number,
) {
  canvas.dispatchEvent(
    new MouseEvent(type, {
      bubbles: type !== "mouseenter",
      composed: true,
      cancelable: true,
      clientX: point.x,
      clientY: point.y,
      button: 0,
      buttons,
    }),
  );
}

function sendWheel(
  canvas: HTMLCanvasElement,
  point: Point,
  deltaX: number,
  deltaY: number,
) {
  canvas.dispatchEvent(
    new WheelEvent("wheel", {
      bubbles: true,
      composed: true,
      cancelable: true,
      clientX: point.x,
      clientY: point.y,
      deltaX,
      deltaY,
      deltaMode: 0,
    }),
  );
}

export function attachTouchInput(host: HTMLElement): () => void {
  const canvas = getCanvas(host);
  if (!canvas) {
    return () => {};
  }

  let mode: TouchMode = "idle";
  let last: Point = { x: 0, y: 0 };
  let pendingX = 0;
  let pendingY = 0;

  const enterCanvas = (point: Point) => {
    if (host.shadowRoot?.activeElement?.tagName === "INPUT") {
      return;
    }
    sendMouse(canvas, "mouseenter", point, 0);
  };

  const endDrag = () => {
    if (mode === "drag") {
      sendMouse(canvas, "mouseup", last, 0);
    }
  };

  const onTouchStart = (event: TouchEvent) => {
    event.preventDefault();

    if (event.touches.length === 1) {
      const point = toPoint(event.touches[0]);
      enterCanvas(point);
      mode = "drag";
      last = point;
      sendMouse(canvas, "mousemove", point, 0);
      sendMouse(canvas, "mousedown", point, 1);
      return;
    }

    if (event.touches.length === 2) {
      endDrag();
      mode = "scroll";
      last = midpoint(event.touches);
      pendingX = 0;
      pendingY = 0;
    }
  };

  const onTouchMove = (event: TouchEvent) => {
    event.preventDefault();

    if (mode === "drag" && event.touches.length === 1) {
      const point = toPoint(event.touches[0]);
      sendMouse(canvas, "mousemove", point, 1);
      last = point;
      return;
    }

    if (mode === "scroll" && event.touches.length === 2) {
      const point = midpoint(event.touches);
      pendingX += last.x - point.x;
      pendingY += last.y - point.y;
      last = point;

      const stepsY = Math.trunc(pendingY / SCROLL_STEP);
      if (stepsY !== 0) {
        pendingY -= stepsY * SCROLL_STEP;
        sendWheel(canvas, point, 0, stepsY * SCROLL_STEP);
        return;
      }

      const stepsX = Math.trunc(pendingX / SCROLL_STEP);
      if (stepsX !== 0) {
        pendingX -= stepsX * SCROLL_STEP;
        sendWheel(canvas, point, stepsX * SCROLL_STEP, 0);
      }
    }
  };

  const onTouchEnd = (event: TouchEvent) => {
    event.preventDefault();
    endDrag();
    mode = "idle";
  };

  const options: AddEventListenerOptions = { passive: false };
  host.addEventListener("touchstart", onTouchStart, options);
  host.addEventListener("touchmove", onTouchMove, options);
  host.addEventListener("touchend", onTouchEnd, options);
  host.addEventListener("touchcancel", onTouchEnd, options);

  return () => {
    host.removeEventListener("touchstart", onTouchStart, options);
    host.removeEventListener("touchmove", onTouchMove, options);
    host.removeEventListener("touchend", onTouchEnd, options);
    host.removeEventListener("touchcancel", onTouchEnd, options);
  };
}
