import { createRoot } from "react-dom/client";
import App from "./App.jsx"; // <-- This is the fix
import "./index.css";
// We are importing styles from index.css now

createRoot(document.getElementById("root")!).render(<App />);