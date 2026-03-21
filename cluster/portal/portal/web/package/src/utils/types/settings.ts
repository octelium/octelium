import * as UserPB from "@octelium/apis/main/userv1/userv1";
interface Settings {
  itemsPerPage?: number;
  status?: UserPB.GetStatusResponse;
}

export default Settings;
