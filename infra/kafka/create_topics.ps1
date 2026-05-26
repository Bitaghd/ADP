$ErrorActionPreference = "Stop"

$topics = @(
    "zeek.conn.raw",
    "traffic.detections",
    "traffic.alerts"
)

foreach ($topic in $topics) {
    docker exec adp-kafka kafka-topics `
        --bootstrap-server localhost:9092 `
        --create `
        --if-not-exists `
        --topic $topic `
        --partitions 3 `
        --replication-factor 1
}

docker exec adp-kafka kafka-topics --bootstrap-server localhost:9092 --list
