const Footer = () => (
  <footer className="flex w-full flex-col items-center justify-center gap-x-1.5 gap-y-1 px-4 pb-6 pt-4 text-xs font-medium text-fg-subtle sm:flex-row">
    <span>Octelium is free and open source software</span>
    <span aria-hidden className="hidden sm:inline">
      ·
    </span>
    <a
      href="https://octelium.com"
      target="_blank"
      className="rounded transition-colors duration-150 hover:text-fg"
    >
      © {new Date().getUTCFullYear()} Octelium Labs, LLC
    </a>
  </footer>
);

export default Footer;
