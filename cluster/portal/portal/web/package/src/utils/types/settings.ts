import * as UserPB from "@/apis/userv1/userv1";
interface Settings {
  itemsPerPage?: number;
  status?: UserPB.GetStatusResponse;
}

export default Settings;
