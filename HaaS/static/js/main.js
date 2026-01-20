// DeceptiBank Frontend JavaScript
document.addEventListener("DOMContentLoaded", () => {
  // Initialize honeypot logging
  logHoneypotActivity("page_load", window.location.pathname)

  // Initialize form handlers
  initializeFormHandlers()

  // Initialize dashboard functionality
  if (document.querySelector(".dashboard-container")) {
    initializeDashboard()
  }

  // Initialize transfer form
  if (document.getElementById("transferForm")) {
    initializeTransferForm()
  }

  // Add suspicious activity detection
  detectSuspiciousActivity()
})

// Honeypot Activity Logging
function logHoneypotActivity(action, data = {}) {
  const activityData = {
    action: action,
    data: data,
    timestamp: new Date().toISOString(),
    user_agent: navigator.userAgent,
    url: window.location.href,
    referrer: document.referrer,
  }

  // Send to backend for logging
  fetch("/api/log_activity", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(activityData),
  }).catch((error) => {
    console.log("Activity logging failed:", error)
  })
}

// Form Handlers
function initializeFormHandlers() {
  // Login form
  const loginForm = document.getElementById("loginForm")
  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      const username = document.getElementById("username").value
      const password = document.getElementById("password").value

      logHoneypotActivity("login_attempt", {
        username: username,
        password_length: password.length,
        has_special_chars: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      })
    })
  }

  // Register form
  const registerForm = document.getElementById("registerForm")
  if (registerForm) {
    registerForm.addEventListener("submit", (e) => {
      const formData = new FormData(registerForm)
      const data = Object.fromEntries(formData)

      logHoneypotActivity("registration_attempt", {
        email: data.email,
        role: data.role,
        username: data.username,
      })
    })
  }
}

// Password Toggle
function togglePassword() {
  const passwordInput = document.getElementById("password")
  const toggleIcon = document.getElementById("passwordToggleIcon")

  if (passwordInput.type === "password") {
    passwordInput.type = "text"
    toggleIcon.classList.remove("fa-eye")
    toggleIcon.classList.add("fa-eye-slash")
  } else {
    passwordInput.type = "password"
    toggleIcon.classList.remove("fa-eye-slash")
    toggleIcon.classList.add("fa-eye")
  }

  logHoneypotActivity("password_toggle", {
    action: passwordInput.type === "text" ? "show" : "hide",
  })
}

// Dashboard Functionality
function initializeDashboard() {
  // Log dashboard access
  logHoneypotActivity("dashboard_access", {
    sections_available: document.querySelectorAll(".dashboard-section").length,
  })

  // Add click tracking to navigation items
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", function (e) {
      const section = this.getAttribute("href").replace("#", "")
      logHoneypotActivity("dashboard_navigation", {
        section: section,
        from_section: document.querySelector(".dashboard-section.active").id,
      })
    })
  })
}

// Show Dashboard Section
function showSection(sectionId) {
  // Hide all sections
  document.querySelectorAll(".dashboard-section").forEach((section) => {
    section.classList.remove("active")
  })

  // Show selected section
  document.getElementById(sectionId).classList.add("active")

  // Update navigation
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.remove("active")
  })

  document.querySelector(`[href="#${sectionId}"]`).classList.add("active")

  // Log section view
  logHoneypotActivity("section_view", {
    section: sectionId,
    timestamp: new Date().toISOString(),
  })
}

// Transfer Form Handler
function initializeTransferForm() {
  const transferForm = document.getElementById("transferForm")

  transferForm.addEventListener("submit", (e) => {
    e.preventDefault()

    const formData = new FormData(transferForm)
    const transferData = {
      from_account: formData.get("from_account"),
      recipient: formData.get("recipient"),
      amount: Number.parseFloat(formData.get("amount")),
      description: formData.get("description"),
    }

    // Log transfer attempt
    logHoneypotActivity("transfer_attempt", transferData)

    // Simulate transfer processing
    showTransferProcessing()

    // Send to backend
    fetch("/api/transfer", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(transferData),
    })
      .then((response) => response.json())
      .then((data) => {
        hideTransferProcessing()
        showTransferResult(data)

        // Reset form
        transferForm.reset()
      })
      .catch((error) => {
        hideTransferProcessing()
        showTransferError()
        console.error("Transfer error:", error)
      })
  })
}

// Transfer UI Functions
function showTransferProcessing() {
  const button = document.querySelector('#transferForm button[type="submit"]')
  button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...'
  button.disabled = true
}

function hideTransferProcessing() {
  const button = document.querySelector('#transferForm button[type="submit"]')
  button.innerHTML = '<i class="fas fa-exchange-alt"></i> Transfer Funds'
  button.disabled = false
}

function showTransferResult(data) {
  const alert = document.createElement("div")
  alert.className = "alert alert-info"
  alert.innerHTML = `
        <i class="fas fa-check-circle"></i>
        ${data.message || "Transfer completed successfully!"}
    `

  const transferSection = document.querySelector(".transfer-section")
  transferSection.insertBefore(alert, transferSection.firstChild)

  // Remove alert after 5 seconds
  setTimeout(() => {
    alert.remove()
  }, 5000)
}

function showTransferError() {
  const alert = document.createElement("div")
  alert.className = "alert alert-danger"
  alert.innerHTML = `
        <i class="fas fa-exclamation-triangle"></i>
        Transfer failed. Please try again later.
    `

  const transferSection = document.querySelector(".transfer-section")
  transferSection.insertBefore(alert, transferSection.firstChild)

  setTimeout(() => {
    alert.remove()
  }, 5000)
}

// Suspicious Activity Detection
function detectSuspiciousActivity() {
  // Monitor for developer tools
  const devtools = {
    open: false,
    orientation: null,
  }

  const threshold = 160

  setInterval(() => {
    if (window.outerHeight - window.innerHeight > threshold || window.outerWidth - window.innerWidth > threshold) {
      if (!devtools.open) {
        devtools.open = true
        logHoneypotActivity("devtools_detected", {
          type: "opened",
          window_dimensions: {
            outer: { width: window.outerWidth, height: window.outerHeight },
            inner: { width: window.innerWidth, height: window.innerHeight },
          },
        })
      }
    } else {
      if (devtools.open) {
        devtools.open = false
        logHoneypotActivity("devtools_detected", {
          type: "closed",
        })
      }
    }
  }, 500)

  // Monitor for right-click (context menu)
  document.addEventListener("contextmenu", (e) => {
    logHoneypotActivity("context_menu", {
      element: e.target.tagName,
      x: e.clientX,
      y: e.clientY,
    })
  })

  // Monitor for key combinations (F12, Ctrl+Shift+I, etc.)
  document.addEventListener("keydown", (e) => {
    if (
      e.key === "F12" ||
      (e.ctrlKey && e.shiftKey && e.key === "I") ||
      (e.ctrlKey && e.shiftKey && e.key === "C") ||
      (e.ctrlKey && e.key === "u")
    ) {
      logHoneypotActivity("suspicious_keypress", {
        key: e.key,
        ctrlKey: e.ctrlKey,
        shiftKey: e.shiftKey,
        altKey: e.altKey,
      })
    }
  })

  // Monitor for copy attempts
  document.addEventListener("copy", (e) => {
    const selectedText = window.getSelection().toString()
    if (selectedText.length > 0) {
      logHoneypotActivity("content_copy", {
        text_length: selectedText.length,
        contains_sensitive: /password|account|balance|transfer/i.test(selectedText),
      })
    }
  })

  // Monitor for unusual mouse behavior
  const mouseMovements = []
  document.addEventListener("mousemove", (e) => {
    mouseMovements.push({
      x: e.clientX,
      y: e.clientY,
      timestamp: Date.now(),
    })

    // Keep only last 10 movements
    if (mouseMovements.length > 10) {
      mouseMovements.shift()
    }

    // Detect rapid movements (potential bot behavior)
    if (mouseMovements.length >= 5) {
      const recent = mouseMovements.slice(-5)
      const timeSpan = recent[4].timestamp - recent[0].timestamp
      const distance = calculateTotalDistance(recent)

      if (timeSpan < 100 && distance > 500) {
        logHoneypotActivity("suspicious_mouse", {
          type: "rapid_movement",
          distance: distance,
          time_span: timeSpan,
        })
      }
    }
  })
}

// Helper function to calculate mouse movement distance
function calculateTotalDistance(movements) {
  let total = 0
  for (let i = 1; i < movements.length; i++) {
    const dx = movements[i].x - movements[i - 1].x
    const dy = movements[i].y - movements[i - 1].y
    total += Math.sqrt(dx * dx + dy * dy)
  }
  return total
}

// Fake data generation for enhanced deception
function generateFakeAccountData() {
  return {
    balance: (Math.random() * 50000 + 10000).toFixed(2),
    last_transaction: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
    account_status: "Active",
    credit_limit: (Math.random() * 20000 + 5000).toFixed(2),
  }
}

// Enhanced form validation with honeypot traps
function validateForm(formElement) {
  const inputs = formElement.querySelectorAll("input, select, textarea")
  const suspiciousInputs = []

  inputs.forEach((input) => {
    const value = input.value

    // Check for SQL injection patterns
    const sqlPatterns = [
      /union\s+select/i,
      /drop\s+table/i,
      /insert\s+into/i,
      /delete\s+from/i,
      /'\s*or\s*'1'\s*=\s*'1/i,
      /'\s*or\s*1\s*=\s*1/i,
    ]

    // Check for XSS patterns
    const xssPatterns = [/<script[^>]*>.*?<\/script>/i, /javascript:/i, /on\w+\s*=/i, /<iframe/i, /eval\s*\(/i]

    // Check for directory traversal
    const traversalPatterns = [/\.\.\//, /\.\.\\/, /%2e%2e%2f/i, /%2e%2e%5c/i]

    let isSuspicious = false
    let attackType = "normal"

    if (sqlPatterns.some((pattern) => pattern.test(value))) {
      isSuspicious = true
      attackType = "sql_injection"
    } else if (xssPatterns.some((pattern) => pattern.test(value))) {
      isSuspicious = true
      attackType = "xss"
    } else if (traversalPatterns.some((pattern) => pattern.test(value))) {
      isSuspicious = true
      attackType = "directory_traversal"
    }

    if (isSuspicious) {
      suspiciousInputs.push({
        field: input.name || input.id,
        value: value,
        attack_type: attackType,
      })
    }
  })

  if (suspiciousInputs.length > 0) {
    logHoneypotActivity("form_attack_detected", {
      form: formElement.id || formElement.className,
      suspicious_inputs: suspiciousInputs,
      total_fields: inputs.length,
    })
  }

  return suspiciousInputs.length === 0
}

// Console warning to deter attackers
console.log("%cSTOP!", "color: red; font-size: 50px; font-weight: bold;")
console.log(
  '%cThis is a browser feature intended for developers. If someone told you to copy-paste something here to enable a feature or "hack" someone\'s account, it is a scam and will give them access to your account.',
  "color: red; font-size: 16px;",
)
console.log("%cSee https://en.wikipedia.org/wiki/Self-XSS for more information.", "color: red; font-size: 16px;")

// Add fake console commands to confuse attackers
window.admin = () => {
  console.log("Access denied. This incident has been logged.")
  logHoneypotActivity("console_admin_attempt", {
    timestamp: new Date().toISOString(),
  })
}

window.debug = () => {
  console.log("Debug mode not available in production.")
  logHoneypotActivity("console_debug_attempt", {
    timestamp: new Date().toISOString(),
  })
}
