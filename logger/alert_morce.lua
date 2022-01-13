--[[

Copyright 2021 CZ.NIC, z.s.p.o

This file is part of Morce, which is free software. It is made
available to you under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version. For more
information, see COPYING.

]]

-- Include required modules
require("snort_plugin")
local uci = require "uci"
local sqlite = require "luasql.sqlite3"

-- Globals to hold open sqlite and uci structures
local db = false
local db_con = false
local u_cur = false

function init()
	-- Initialize SQLite
	db = sqlite.sqlite3()
	if not db then
		return false
	end

	-- Initialize UCI
	u_cur = uci.cursor()

	-- Open the database
	local db_path = u_cur:get("morce", "setup", "live_database") or "/var/run/morce/morce-alerts.sqlite"
	db_con = db:connect(db_path)
	if not db_con then
		return false
	end

	-- WAL should be faster and better for concurrent access
	db_con:execute([[PRAGMA journal_mode = WAL]])
	-- We also prefer to do DB maintenance manually as we only add data from snort plugin
	db_con:execute([[PRAGMA auto_vacuum = NONE]])
	-- But we do need foreign keys for consistency
	db_con:execute([[PRAGMA foreign_keys = ON]])

	-- Create tables and view if they don't exist yet
	db_con:execute([[
		CREATE TABLE IF NOT EXISTS alert_messages(
			alert_id char(20) NOT NULL PRIMARY KEY ON CONFLICT REPLACE, msg text default "" NOT NULL
		) WITHOUT ROWID;
	]])
	db_con:execute([[
		CREATE TABLE IF NOT EXISTS live_alerts(
			time timestamp default current_timestamp NOT NULL,
			alert_id varchar(20) default "" REFERENCES alert_messages(alert_id) ON DELETE RESTRICT NOT NULL,
			mac varchar(20) default "" NOT NULL,
			dst_ip varchar(50) default "" NOT NULL,
			dst_port integer default 0 NOT NULL
		);
	]])
	return true
end

function alert()
	-- Get data from the event
	local evt = ffi.C.get_event()
	local pkt = ffi.C.get_packet()
	local alert_id = string.format("%d:%d:%d", evt.gid, evt.sid, evt.rev)
	local msg = ffi.string(evt.msg)
	local src_eth = string.upper(ffi.string(pkt.ether_src))
	local dst_ip = string.lower(ffi.string(pkt.dst_addr))

	-- Print data for logger
	print(string.format([['Security alert from host %s to %s:%d%s%s']],
						  src_eth, dst_ip, pkt.dp, " - ", msg))
	-- Log data into database
	db_con:execute(string.format(
		[[INSERT OR REPLACE INTO alert_messages VALUES ('%s','%s')]],
		alert_id, db_con:escape(msg)))
	db_con:execute(string.format(
		[[INSERT INTO live_alerts (alert_id,mac,dst_ip,dst_port) VALUES ('%s','%s','%s',%d)]],
		alert_id, db_con:escape(src_eth), db_con:escape(dst_ip), pkt.dp))

	-- Create a notification
	local notify = u_cur:get("morce", "notify", "enabled") or 1
	if notify == 1 then
		local notify_cmd = u_cur:get("morce", "notify", "command") or "create_notification -s error"
		os.execute(string.format(
			[[%s 'Security alert from host %s to %s:%d%s%s']],
			u_cur:get("morce", "notify", "command"), src_eth, dst_ip, pkt.dp, "\n", msg))
	end
end

-- plugin table to register ourselves in snort
plugin = {
	type = "logger",
	name = "alert_morce",
	version = "1.1"
}
