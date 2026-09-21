export const ITEMS_PER_PAGE_STORAGE_KEY = "octelium-portal-items-per-page";

export const ITEMS_PER_PAGE_OPTIONS = [10, 20, 50, 100];

export const DEFAULT_ITEMS_PER_PAGE = 10;

export const isValidItemsPerPage = (value: number): boolean =>
  Number.isFinite(value) && ITEMS_PER_PAGE_OPTIONS.includes(value);

export const loadItemsPerPage = (): number => {
  try {
    const stored = window.localStorage.getItem(ITEMS_PER_PAGE_STORAGE_KEY);
    if (!stored) {
      return DEFAULT_ITEMS_PER_PAGE;
    }

    const parsed = Number(stored);
    return isValidItemsPerPage(parsed) ? parsed : DEFAULT_ITEMS_PER_PAGE;
  } catch (e) {
    void e;
    return DEFAULT_ITEMS_PER_PAGE;
  }
};

export const saveItemsPerPage = (itemsPerPage: number) => {
  try {
    window.localStorage.setItem(
      ITEMS_PER_PAGE_STORAGE_KEY,
      String(itemsPerPage),
    );
  } catch (e) {
    void e;
  }
};
