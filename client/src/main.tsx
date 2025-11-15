import { createRoot } from "react-dom/client";
import App from "./App.jsx"; // <-- This is the fix
import "./index.css";
import { ThemeProvider } from 'next-themes';

// We are importing styles from index.css now

createRoot(document.getElementById("root")!).render(
  <ThemeProvider defaultTheme="dark">
    <App />
  </ThemeProvider>
);
