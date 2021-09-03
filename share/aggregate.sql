-- WAL should be faster and better for concurrent access
PRAGMA journal_mode = WAL;
-- We also prefer to do DB maintenance manually at the end
PRAGMA auto_vacuum = NONE;
-- But we do need foreign keys for consistency
PRAGMA foreign_keys = ON;

/*
 Create aggregated table
 'aggregation' column can contain:
 - H - hourly aggregated
 - D - daily aggregated
*/
CREATE TABLE IF NOT EXISTS aggregated_alerts (
      time TIMESTAMP NOT NULL,
      aggregation CHAR(1) NOT NULL,
      count INTEGER default 0 NOT NULL,
      mac VARCHAR(20) default "" NOT NULL,
      alert_id VARCHAR(20) default "" NOT NULL,
      dst_ip VARCHAR(50) default "" NOT NULL,
      dst_port INTEGER default 0 NOT NULL,
      CHECK(aggregation GLOB '[DM]')
);

-- Create temp table for variables as sqlite does not support variables
PRAGMA temp_store = MEMORY
CREATE TEMP TABLE timestamps (
    name VARCHAR(10) PRIMARY KEY,
    stamp TIMESTAMP
);

-- Anything older then week we aggregate per hour
INSERT INTO timestamps VALUES ("week_ago", datetime("now", "-7 days"));
INSERT INTO aggregated_alerts(
        time, aggregation, count, mac, alert_id, dst_ip, dst_port
    ) SELECT
        strftime("%Y-%m-%d %H:00:00", time),
        "H",
        count(time),
        mac,
        alert_id,
        dst_ip,
        dst_port 
    FROM live_alerts WHERE
        time < (
            SELECT stamp 
            FROM timestamps 
            WHERE name = "week_ago"
        )
    GROUP BY
        strftime("%Y-%m-%d %H:00:00", time),
        mac,
        alert_id,
        dst_ip,
        dst_port;
DELETE FROM live_alerts WHERE time < (
        SELECT stamp 
        FROM timestamps 
        WHERE name = "week_ago"
    );

-- Anything older then month we aggregate per day
INSERT INTO timestamps VALUES ("month_ago", DATETIME("now", "-1 months"));
INSERT INTO aggregated_alerts(
        time, aggregation, count, mac, alert_id, dst_ip, dst_port
    ) SELECT
        strftime("%Y-%m-%d 00:00:00", time),
        "D",
        sum(count),
        mac,
        alert_id,
        "",
        0 
    FROM aggregated_alerts WHERE
        time < (
            SELECT stamp 
            FROM timestamps 
            WHERE name = "week_ago"
        ) AND aggregation = "H"
    GROUP BY
        strftime("%Y-%m-%d 00:00:00", time),
        mac,
        alert_id;
DELETE FROM aggregated_alerts WHERE time < (
        SELECT stamp 
        FROM timestamps 
        WHERE name = "week_ago"
    ) AND aggregation = "H";

-- Cleanup table
VACUUM;
