import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Wizard } from "../components/Wizard";
import type { WizardStepDef } from "../components/Wizard";

function threeStepWizard(overrides: Partial<Record<string, unknown>> = {}) {
  const onComplete = vi.fn();
  const onCancel = vi.fn();

  const steps: WizardStepDef[] = [
    {
      id: "one",
      title: "One",
      validate: () => (overrides.blockStepOne ? "step one is invalid" : null),
      render: () => <div>Step one content</div>,
    },
    {
      id: "two",
      title: "Two",
      render: () => <div>Step two content</div>,
    },
    {
      id: "three",
      title: "Three",
      render: () => <div>Step three content</div>,
    },
  ];

  render(<Wizard steps={steps} onComplete={onComplete} onCancel={onCancel} />);
  return { onComplete, onCancel };
}

describe("Wizard", () => {
  it("renders the first step and blocks Next when validate returns an error", async () => {
    const user = userEvent.setup();
    threeStepWizard({ blockStepOne: true });

    expect(screen.getByText("Step one content")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByRole("alert")).toHaveTextContent("step one is invalid");
    expect(screen.getByText("Step one content")).toBeInTheDocument();
  });

  it("advances to the next step when validate returns null", async () => {
    const user = userEvent.setup();
    threeStepWizard();

    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByText("Step two content")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("Back decrements the step and Back is disabled on the first step", async () => {
    const user = userEvent.setup();
    threeStepWizard();

    expect(screen.getByRole("button", { name: "Back" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Step two content")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByText("Step one content")).toBeInTheDocument();
  });

  it("shows Finish on the last step and calls onComplete", async () => {
    const user = userEvent.setup();
    const { onComplete } = threeStepWizard();

    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByText("Step three content")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Next" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Finish" }));
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  // S-18/G-80: Finish must validate the active (last) step exactly like
  // Next validates every other step -- before this fix, Finish called
  // onComplete() unconditionally, silently skipping the last step's own
  // validate().
  it("blocks Finish when the last step's validate returns an error", async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    const steps: WizardStepDef[] = [
      {
        id: "only",
        title: "Only",
        validate: () => "last step is invalid",
        render: () => <div>Only step content</div>,
      },
    ];

    render(<Wizard steps={steps} onComplete={onComplete} />);

    await user.click(screen.getByRole("button", { name: "Finish" }));

    expect(screen.getByRole("alert")).toHaveTextContent("last step is invalid");
    expect(onComplete).not.toHaveBeenCalled();
  });

  it("marks the active step with aria-current for a11y", async () => {
    const user = userEvent.setup();
    threeStepWizard();

    const list = screen.getByRole("list");
    expect(list.querySelector('[aria-current="step"]')).toHaveTextContent(
      "One",
    );

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(list.querySelector('[aria-current="step"]')).toHaveTextContent(
      "Two",
    );
  });

  it("renders an optional summary/review step before Finish", async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    const steps: WizardStepDef[] = [
      { id: "one", title: "One", render: () => <div>Step one content</div> },
    ];

    render(
      <Wizard
        steps={steps}
        onComplete={onComplete}
        summary={() => <div>Review content</div>}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Review content")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Finish" }));
    expect(onComplete).toHaveBeenCalledTimes(1);
  });
});
