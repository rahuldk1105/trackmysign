import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { applyTheme, loadThemePref } from "./theme";
import "./styles.css";

// Before the first render, so the window never flashes the wrong theme.
applyTheme(loadThemePref());

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
