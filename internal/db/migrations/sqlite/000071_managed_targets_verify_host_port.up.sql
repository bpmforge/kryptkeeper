-- Optional post-install verification address for scheduled renewals (host:port); empty = <host>:443.
ALTER TABLE managed_targets ADD COLUMN verify_host_port TEXT;
