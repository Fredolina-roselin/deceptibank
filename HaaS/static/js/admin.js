import { Chart } from "@/components/ui/chart"
// Admin Dashboard JavaScript for Real-time Monitoring
class AdminDashboard {
  constructor() {
    this.socket = null
    this.charts = {}
    this.initializeWebSocket()
    this.initializeCharts()
    this.bindEvents()
    this.startRealTimeUpdates()
  }

  initializeWebSocket() {
    // Initialize WebSocket for real-time updates
    this.socket = new WebSocket(`ws://${window.location.host}/ws`)

    this.socket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      this.handleRealTimeUpdate(data)
    }

    this.socket.onclose = () => {
      console.log("[v0] WebSocket connection closed, attempting to reconnect...")
      setTimeout(() => this.initializeWebSocket(), 5000)
    }
  }

  initializeCharts() {
    // Initialize threat level chart
    const threatCtx = document.getElementById("threatChart")
    if (threatCtx) {
      this.charts.threat = new Chart(threatCtx, {
        type: "doughnut",
        data: {
          labels: ["Low", "Medium", "High", "Critical"],
          datasets: [
            {
              data: [0, 0, 0, 0],
              backgroundColor: ["#10b981", "#f59e0b", "#ef4444", "#dc2626"],
            },
          ],
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: "bottom" },
          },
        },
      })
    }

    // Initialize attack timeline chart
    const timelineCtx = document.getElementById("timelineChart")
    if (timelineCtx) {
      this.charts.timeline = new Chart(timelineCtx, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "Attacks per Hour",
              data: [],
              borderColor: "#ef4444",
              backgroundColor: "rgba(239, 68, 68, 0.1)",
              tension: 0.4,
            },
          ],
        },
        options: {
          responsive: true,
          scales: {
            y: { beginAtZero: true },
          },
        },
      })
    }
  }

  bindEvents() {
    // Bind event listeners
    document.addEventListener("DOMContentLoaded", () => {
      this.loadInitialData()
    })

    // Export logs functionality
    const exportBtn = document.getElementById("exportLogs")
    if (exportBtn) {
      exportBtn.addEventListener("click", () => this.exportLogs())
    }

    // Block IP functionality
    document.addEventListener("click", (e) => {
      if (e.target.classList.contains("block-ip-btn")) {
        const ip = e.target.dataset.ip
        this.blockIP(ip)
      }
    })

    // Refresh data button
    const refreshBtn = document.getElementById("refreshData")
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => this.refreshDashboard())
    }
  }

  async loadInitialData() {
    try {
      const response = await fetch("/api/admin/dashboard-data")
      const data = await response.json()
      this.updateDashboard(data)
    } catch (error) {
      console.error("[v0] Error loading dashboard data:", error)
    }
  }

  handleRealTimeUpdate(data) {
    switch (data.type) {
      case "new_attack":
        this.addNewAttack(data.attack)
        break
      case "threat_update":
        this.updateThreatLevels(data.threats)
        break
      case "system_alert":
        this.showAlert(data.message, data.severity)
        break
    }
  }

  addNewAttack(attack) {
    const attacksList = document.getElementById("recentAttacks")
    if (attacksList) {
      const attackElement = this.createAttackElement(attack)
      attacksList.insertBefore(attackElement, attacksList.firstChild)

      // Keep only latest 10 attacks visible
      const attacks = attacksList.children
      if (attacks.length > 10) {
        attacksList.removeChild(attacks[attacks.length - 1])
      }
    }

    // Update counters
    this.updateCounters()
  }

  createAttackElement(attack) {
    const div = document.createElement("div")
    div.className = `attack-item severity-${attack.severity}`
    div.innerHTML = `
            <div class="attack-header">
                <span class="attack-type">${attack.attack_type}</span>
                <span class="attack-time">${new Date(attack.timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="attack-details">
                <span class="attack-ip">IP: ${attack.ip_address}</span>
                <span class="attack-location">${attack.location || "Unknown"}</span>
            </div>
            <div class="attack-payload">
                <code>${attack.payload.substring(0, 100)}${attack.payload.length > 100 ? "..." : ""}</code>
            </div>
            <div class="attack-actions">
                <button class="btn-small block-ip-btn" data-ip="${attack.ip_address}">Block IP</button>
                <button class="btn-small view-details-btn" data-id="${attack.id}">Details</button>
            </div>
        `
    return div
  }

  async blockIP(ip) {
    try {
      const response = await fetch("/api/admin/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip_address: ip }),
      })

      if (response.ok) {
        this.showAlert(`IP ${ip} has been blocked`, "success")
      } else {
        this.showAlert("Failed to block IP", "error")
      }
    } catch (error) {
      console.error("[v0] Error blocking IP:", error)
      this.showAlert("Error blocking IP", "error")
    }
  }

  async exportLogs() {
    try {
      const response = await fetch("/api/admin/export-logs")
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `deceptibank_logs_${new Date().toISOString().split("T")[0]}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error("[v0] Error exporting logs:", error)
      this.showAlert("Failed to export logs", "error")
    }
  }

  updateCounters() {
    fetch("/api/admin/counters")
      .then((response) => response.json())
      .then((data) => {
        document.getElementById("totalAttacks").textContent = data.total_attacks
        document.getElementById("activeThreats").textContent = data.active_threats
        document.getElementById("blockedIPs").textContent = data.blocked_ips
        document.getElementById("uniqueAttackers").textContent = data.unique_attackers
      })
      .catch((error) => console.error("[v0] Error updating counters:", error))
  }

  showAlert(message, type) {
    const alertContainer = document.getElementById("alertContainer")
    if (alertContainer) {
      const alert = document.createElement("div")
      alert.className = `alert alert-${type}`
      alert.innerHTML = `
                <span>${message}</span>
                <button class="alert-close" onclick="this.parentElement.remove()">×</button>
            `
      alertContainer.appendChild(alert)

      // Auto-remove after 5 seconds
      setTimeout(() => {
        if (alert.parentElement) {
          alert.remove()
        }
      }, 5000)
    }
  }

  startRealTimeUpdates() {
    // Update dashboard every 30 seconds
    setInterval(() => {
      this.updateCounters()
    }, 30000)
  }

  refreshDashboard() {
    this.loadInitialData()
    this.updateCounters()
    this.showAlert("Dashboard refreshed", "success")
  }
}

// Initialize dashboard when page loads
document.addEventListener("DOMContentLoaded", () => {
  new AdminDashboard()
})
