import { PinInput } from "@mantine/core";

const CodeInput = (props: {
  value: string;
  disabled?: boolean;
  onChange: (value: string) => void;
  onComplete: (value: string) => void;
}) => (
  <PinInput
    type={"number"}
    inputType="number"
    inputMode="numeric"
    length={6}
    size="lg"
    autoFocus
    placeholder=""
    ariaLabel="Verification code"
    classNames={{
      root: "w-full flex-nowrap justify-center",
      pinInput: "min-w-0 flex-1 max-w-[3.125rem]",
    }}
    value={props.value}
    disabled={props.disabled}
    onChange={props.onChange}
    onComplete={props.onComplete}
  />
);

export default CodeInput;
