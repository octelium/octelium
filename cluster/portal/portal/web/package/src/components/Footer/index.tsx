const Footer = () => (
  <footer className="mt-auto flex w-full flex-col items-center justify-center gap-x-1.5 gap-y-1 pb-6 pt-10 text-xs font-normal text-slate-500 sm:flex-row">
    <span>Octelium is free and open source software</span>
    <span aria-hidden className="hidden text-slate-300 sm:inline">
      ·
    </span>
    <a
      href="https://octelium.com"
      target="_blank"
      className="rounded transition-colors duration-150 hover:text-slate-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-400"
    >
      © {new Date().getFullYear()} Octelium Labs, LLC
    </a>
  </footer>
);

export default Footer;
