const std = @import("std");
const pos = std.posix;

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
const ICMPPacket = packed struct {
    type: u8 = 8,
    code: u8 = 0,
    checksum: u16 = 0,
    identifier: u16 = 24, //todo random
    seq: u16 = 0x0001,
    data: u448 = 0,
};

const PingStatus = enum { OK, TIMEOUT, BAD_SUM };

const MAX_SEQUENCE = 10;
const socket_t = pos.socket_t;

pub fn main() !void {
    var sequence: u16 = 0;
    const sok = std.posix.socket(pos.AF.INET, pos.SOCK.RAW, pos.IPPROTO.ICMP) catch {
        std.debug.print("Couldn't open raw socket, do you have privilages?", .{});
        return;
    };

    const ttl_val: [4]u8 = .{ 64, 0, 0, 0 };
    try pos.setsockopt(sok, pos.SOL.IP, 2, ttl_val[0..]);
    defer pos.close(sok);

    const ipstr = "1.1.1.1";
    // const ipstr = "192.168.8.8";

    const addr = try std.net.Ip4Address.resolveIp(ipstr, 0);
    const saddr: pos.sockaddr = @bitCast(addr.sa);

    std.debug.print("PING {s} {d} bytes of data.", .{ ipstr, @sizeOf(ICMPPacket) + 20 });

    var icmp = ICMPPacket{ .seq = sequence };

    for (0..MAX_SEQUENCE) |_| {
        icmp.seq = sequence;
        populate_checksum(&icmp);
        const packet: [64]u8 = @bitCast(icmp);
        _ = try pos.sendto(sok, &packet, 64, &saddr, addr.getOsSockLen());
        const start_time = std.time.microTimestamp();
        const status = try waitForEcho(sok, 0);
        const end_time = std.time.microTimestamp();
        const rtt: f32 = @as(f32, @floatFromInt(end_time - start_time)) / 1000.0;
        switch (status) {
            .OK => std.debug.print("{s} responded, icmp_seq={d}  time={d:.3}ms\n", .{ ipstr, sequence, rtt }),
            .BAD_SUM => std.debug.print("Bad checksum for icmp_seq={d}", .{sequence}),
            .TIMEOUT => std.debug.print("Timeout for icmp_seq={d}", .{sequence}),
        }
        sequence += 1;
        std.time.sleep(std.time.ns_per_s);
    }
}

fn waitForEcho(socket: socket_t, id: u16) !PingStatus {
    _ = id;
    var buff: [512]u8 = std.mem.zeroes([512]u8);
    var offset: usize = 0;

    var fds = [_]pos.pollfd{pos.pollfd{ .fd = socket, .events = 0, .revents = 0 }};
    const status = try pos.poll(fds[0..1], 0);
    if (status != -1) {
        const bytesRead = pos.recv(socket, buff[offset..], 0) catch 0;
        offset += bytesRead;
        if (offset >= 20) {

            // skip ahead of ipv4 header
            const header_size: u8 = (buff[0] & 0x0F) * 4;

            var replyICMPbytes: [@sizeOf(ICMPPacket)]u8 = undefined;
            std.mem.copyForwards(u8, &replyICMPbytes, buff[header_size .. header_size + 64]);
            var replyICMP: ICMPPacket = @bitCast(replyICMPbytes);
            const ok = check_checksum(&replyICMP);
            if (ok) {
                return .OK;
            } else {
                return .BAD_SUM;
            }
        }
    }

    return .TIMEOUT;
}

fn populate_checksum(icmp: *ICMPPacket) void {
    icmp.checksum = 0;
    icmp.checksum = calculate_checksum(icmp);
}
fn check_checksum(icmp: *ICMPPacket) bool {
    const old_sum = icmp.checksum;
    icmp.checksum = 0;
    defer icmp.checksum = old_sum;
    const calculated_sum = calculate_checksum(icmp);

    return calculated_sum == old_sum;
}
fn calculate_checksum(icmp: *ICMPPacket) u16 {
    const array: [@sizeOf(ICMPPacket)]u8 = @bitCast(icmp.*);
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < array.len) : (i += 2) {
        const upperByte = @as(u16, @intCast(array[i])) << 8;
        const lowerByte = @as(u16, @intCast(array[i + 1]));
        const combinedValue = upperByte | lowerByte;
        sum += combinedValue;
    }

    const lowerByte = @as(u8, @intCast(~sum & 0xFF));
    const upperByte = @as(u8, @intCast(~sum >> 8));
    return @bitCast([_]u8{ upperByte, lowerByte });
}
