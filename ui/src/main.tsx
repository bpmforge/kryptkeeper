import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { ThemeProvider } from "next-themes";

async function bootstrap() {
  if (import.meta.env.DEV) {
    const { worker } = await import("./mocks/browser");
    await worker.start({
      onUnhandledRequest: "bypass", // don't warn about vite HMR / font requests
    });
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      {/* defaultTheme="system" so an untouched install follows the OS.
          disableTransitionOnChange stops every colour transition in the
          app firing at once while the theme swaps. */}
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        <App />
      </ThemeProvider>
    </StrictMode>,
  );
}

bootstrap();
