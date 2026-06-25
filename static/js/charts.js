window.addEventListener("load", () => {
    if (typeof Chart === "undefined") return;

    Chart.defaults.color = "#8a95a5";
    Chart.defaults.font.family = "DM Sans";
    Chart.defaults.font.size = 11;

    const protocolCanvas = document.getElementById("protocolChart");

    if (protocolCanvas && typeof tcpCount !== "undefined") {
        new Chart(protocolCanvas, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP"],
                datasets: [{
                    data: [tcpCount, udpCount],
                    backgroundColor: ["#7aa7ff", "#3dd6b3"],
                    borderColor: "#151922",
                    borderWidth: 4,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "72%",
                plugins: {
                    legend: {
                        position: "right",
                        labels: { usePointStyle: true, pointStyle: "rectRounded", padding: 18, boxWidth: 8 }
                    }
                }
            }
        });
    }

    const severityCanvas = document.getElementById("severityChart");

    if (severityCanvas && typeof severityData !== "undefined") {
        new Chart(severityCanvas, {
            type: "bar",
            data: {
                labels: ["High", "Medium", "Low"],
                datasets: [{
                    data: severityData,
                    backgroundColor: ["#ff6b7a", "#f6b95a", "#4fd084"],
                    borderRadius: 4,
                    borderSkipped: false,
                    barThickness: 28
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false }, border: { display: false } },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 },
                        grid: { color: "rgba(255, 255, 255, 0.07)" },
                        border: { display: false }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
});
