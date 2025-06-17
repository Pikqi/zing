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
    std.debug.print("{d}", .{packet});
}

fn populate_checksum(icmp: *ICMPPacket) void {
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
    icmp.checksum = @bitCast([_]u8{ upperByte, lowerByte });
}
