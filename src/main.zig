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

pub fn main() !void {
    const sequence: u16 = 0;
    const sok = std.posix.socket(pos.AF.INET, pos.SOCK.RAW, pos.IPPROTO.ICMP) catch {
        std.debug.print("Couldn't open raw socket, do you have privilages?", .{});
        return;
    };

    const ttl_val: [4]u8 = .{ 64, 0, 0, 0 };
    try pos.setsockopt(sok, pos.SOL.IP, 2, ttl_val[0..]);
    defer pos.close(sok);

    const ipstr = "1.1.1.1";

    const addr = try std.net.Ip4Address.resolveIp(ipstr, 0);
    const saddr: pos.sockaddr = @bitCast(addr.sa);

    var icmp = ICMPPacket{ .seq = sequence };
    populate_checksum(&icmp);

    const packet: [64]u8 = @bitCast(icmp);

    const sizesent = try pos.sendto(sok, &packet, 64, &saddr, addr.getOsSockLen());

    std.debug.print("s: {d} soket: {d}", .{ sizesent, sok });
    var buff: [512]u8 = std.mem.zeroes([512]u8);
    for (0..10) |_| {
        const bytesRead = try pos.recvfrom(sok, &buff, 0, null, null);
        if (bytesRead > 0) {

            // skip ahead of ipv4 header
            const header_size: u8 = (buff[0] & 0x0F) * 4;
            std.debug.print("hs: {d}", .{header_size});

            var replyICMPbytes: [@sizeOf(ICMPPacket)]u8 = undefined;
            std.mem.copyForwards(u8, &replyICMPbytes, buff[header_size .. header_size + 64]);
            var replyICMP: ICMPPacket = @bitCast(replyICMPbytes);
            const ok = check_checksum(&replyICMP);
            std.debug.print("ok: {}", .{ok});

            break;
        }
        std.time.sleep(std.time.ns_per_s / 10);
    }
}

fn populate_checksum(icmp: *ICMPPacket) void {
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
