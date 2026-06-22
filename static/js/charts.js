window.onload = function () {

    // Protocol Chart
    const protocolCanvas = document.getElementById("protocolChart");

    if (protocolCanvas && typeof tcpCount !== "undefined") {

        new Chart(protocolCanvas, {

            type: "doughnut",

            data: {

                labels: ["TCP", "UDP"],

                datasets: [{
                    data: [tcpCount, udpCount],
                    borderWidth: 2
                }]

            }

        });

    }


    // Severity Chart
    const severityCanvas = document.getElementById("severityChart");

    if (severityCanvas && typeof severityData !== "undefined") {

        new Chart(severityCanvas, {

            type: "bar",

            data: {

                labels: ["HIGH", "MEDIUM", "LOW"],

                datasets: [{
                    label: "Alerts",
                    data: severityData,
                    borderWidth: 1
                }]

            },

            options: {

                responsive: true,

                scales: {
                    y: {
                        beginAtZero: true
                    }
                },

                plugins: {
                    legend: {
                        display: false
                    }
                }

            }

        });

    }

};