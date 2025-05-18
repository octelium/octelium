import { createSlice } from "@reduxjs/toolkit";
import { PayloadAction } from "@reduxjs/toolkit";
import Settings from "@/utils/types/settings";

import * as UserPB from "@/apis/userv1/userv1";

export const slice = createSlice({
  name: "settings",
  initialState: {
    itemsPerPage: 10,
  } as Settings,
  reducers: {
    setItemsPerPage: (
      state,
      action: PayloadAction<{ itemsPerPage: number }>
    ) => {
      state.itemsPerPage = action.payload.itemsPerPage;
    },

    setStatus: (
      state,
      action: PayloadAction<{ status: UserPB.GetStatusResponse }>
    ) => {
      state.status = action.payload.status;
    },
  },
});

export const { setItemsPerPage, setStatus } = slice.actions;

export default slice.reducer;
