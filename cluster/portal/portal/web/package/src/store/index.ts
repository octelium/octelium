import { configureStore } from "@reduxjs/toolkit";
import settingsReducer from "../features/settings/slice";
import { saveItemsPerPage } from "@/utils/preferences";

const store = configureStore({
  reducer: {
    settings: settingsReducer,
  },
});

let lastItemsPerPage = store.getState().settings.itemsPerPage;

store.subscribe(() => {
  const itemsPerPage = store.getState().settings.itemsPerPage;
  if (itemsPerPage === lastItemsPerPage) {
    return;
  }

  lastItemsPerPage = itemsPerPage;

  if (typeof itemsPerPage === "number") {
    saveItemsPerPage(itemsPerPage);
  }
});

export default store;

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
