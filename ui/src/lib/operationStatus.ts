import type { OperationEvent } from "../hooks/useOperationEvents";

type Status = OperationEvent["status"];

// Wire status is "completed"; "Succeeded" is a display label only.
export function opLabel(status: Status): string {
  return status === "completed" ? "Succeeded" : status;
}

export function opTone(status: Status): "success" | "danger" | "warning" | "info" {
  switch (status) {
    case "completed":
      return "success";
    case "failed":
      return "danger";
    case "cancelled":
      return "warning";
    default:
      return "info";
  }
}
