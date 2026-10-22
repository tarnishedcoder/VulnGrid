import React, { useEffect, useMemo, useState } from "react";
import { DataGrid, GridToolbar } from "@mui/x-data-grid";
import {
  Box,
  Chip,
  Container,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Select,
  TextField,
  Typography,
} from "@mui/material";
import axios from "axios";

const API_URL = import.meta.env.VITE_BACKEND_URL || "http://localhost:8000";

function riskScore(row) {
  const cvss = row.cvss ?? 0;
  const epss = row.epss ?? 0;
  return Math.round(cvss * epss * 10 * 100) / 100;
}

function severityColor(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "success";
    default:
      return "default";
  }
}

const columns = [
  { field: "id", headerName: "ID", width: 70 },
  { field: "title", headerName: "Title", flex: 1, minWidth: 220 },
  {
    field: "severity",
    headerName: "Severity",
    width: 120,
    renderCell: (params) => (
      <Chip label={params.value || "Unknown"} color={severityColor(params.value)} size="small" />
    ),
  },
  {
    field: "risk",
    headerName: "Risk (0-100)",
    width: 160,
    valueGetter: (value, row) => riskScore(row),
    renderCell: (params) => {
      const val = params.value ?? 0;
      const color = val > 70 ? "error" : val > 40 ? "warning" : "success";
      return (
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
          <LinearProgress variant="determinate" value={Math.min(100, val)} color={color} sx={{ flex: 1 }} />
          <Typography variant="caption">{val}</Typography>
        </Box>
      );
    },
  },
  { field: "cvss", headerName: "CVSS", width: 80 },
  { field: "epss", headerName: "EPSS", width: 80 },
  { field: "tool", headerName: "Tool", width: 130 },
  { field: "status", headerName: "Status", width: 130 },
  { field: "cve", headerName: "CVE", width: 160 },
];

export default function App() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All");

  useEffect(() => {
    axios
      .get(`${API_URL}/findings/`)
      .then((res) => setFindings(res.data))
      .catch((err) => setError(`Cannot reach backend at ${API_URL}: ${err.message}`))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      const matchesSev = severity === "All" || (f.severity || "").toLowerCase() === severity.toLowerCase();
      const q = query.toLowerCase();
      const matchesQuery =
        !q ||
        (f.title || "").toLowerCase().includes(q) ||
        (f.tool || "").toLowerCase().includes(q) ||
        (f.cve || "").toLowerCase().includes(q);
      return matchesSev && matchesQuery;
    });
  }, [findings, query, severity]);

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Security Findings Dashboard
      </Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Backend: {API_URL} &middot; Risk = CVSS &times; EPSS &times; 10 (0&ndash;100)
      </Typography>
      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <TextField
          label="Filter (title, tool, CVE)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          size="small"
          sx={{ flex: 1 }}
        />
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Severity</InputLabel>
          <Select value={severity} label="Severity" onChange={(e) => setSeverity(e.target.value)}>
            {["All", "Critical", "High", "Medium", "Low"].map((s) => (
              <MenuItem key={s} value={s}>
                {s}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>
      {error && (
        <Typography color="error" gutterBottom>
          {error}
        </Typography>
      )}
      <Box sx={{ height: 600, width: "100%" }}>
        <DataGrid
          rows={filtered}
          columns={columns}
          loading={loading}
          pageSizeOptions={[25, 50, 100]}
          initialState={{ pagination: { paginationModel: { pageSize: 25 } } }}
          slots={{ toolbar: GridToolbar }}
        />
      </Box>
    </Container>
  );
}
