import Foundation
import Testing
@testable import VaultKit

@Suite(.serialized) struct VaultTests {
    static let reader: String = {
        try! Vault.enableMock(cards: 1, demo: true, touchMs: 0)
        // Mock ids count mocks only, so a plugged-in YubiKey doesn't shift them.
        return try! Vault.listCards().last { $0.mock == true }!.id
    }()

    func unlocked() throws -> Session {
        let s = try Session.open(Self.reader)
        try s.unlock("correct horse battery staple")
        return s
    }

    @Test func testUnlockListRevealTotp() throws {
        let s = try unlocked()
        defer { s.close() }
        let github = try s.entries(host: "github.com")
        XCTAssertEqual(github.first?.name, "GitHub")
        XCTAssertEqual(github.first?.username, "octocat")
        let id = github[0].numericId
        XCTAssertEqual(try s.reveal(id, field: 1), "correct-horse-battery")
        let (code, left) = try s.totp(id, at: Date(timeIntervalSince1970: 59))
        XCTAssertEqual(code, "287082")
        XCTAssertEqual(left, 1)
        XCTAssertGreaterThan(try s.capacity().used, 0)
    }

    @Test func testWrongPassphrase() throws {
        let s = try Session.open(Self.reader)
        defer { s.close() }
        XCTAssertThrowsError(try s.unlock("nope nope nope")) { e in
            XCTAssertTrue((e as? VaultError)?.isWrongPin ?? false)
        }
        XCTAssertFalse(s.isUnlocked)
        XCTAssertEqual(try s.pinTriesLeft(), 254)
        try s.unlock("correct horse battery staple")
        XCTAssertEqual(try s.pinTriesLeft(), 255)
    }

    @Test func testUpsertAndDelete() throws {
        let s = try unlocked()
        defer { s.close() }
        let draft = EntryDraft(id: nil, kind: EntryKind.login, name: "Ünïcode \"quoted\"", hosts: ["example.org"],
                               fields: [.init(kind: FieldKind.password, value: "pä$$")])
        let id = try s.upsert(draft)
        XCTAssertEqual(try s.reveal(id, field: 0), "pä$$")
        XCTAssertEqual(try s.entries(host: "example.org").first?.name, "Ünïcode \"quoted\"")
        try s.delete(id)
        XCTAssertTrue(try s.entries(host: "example.org").isEmpty)
    }

    @Test func testGenerators() throws {
        XCTAssertEqual(try Vault.password(length: 20, flags: 15).count, 20)
        XCTAssertEqual(try Vault.passphrase(words: 6).split(separator: "-").count, 6)
    }

    @Test func testBackupKeyAndExports() throws {
        let s = try unlocked()
        defer { s.close() }
        try Vault.enableMock(cards: 1, demo: false, touchMs: 0)
        let backup = try Vault.listCards().last { $0.mock == true && !$0.has_vault }!.id
        try s.cloneTo(backup, label: "Spare")
        var keys = try s.knownKeys()
        XCTAssertEqual(keys.keys.count, 2)
        XCTAssertFalse(keys.keys.contains { keys.isBehind($0) })
        let id = try s.upsert(EntryDraft(id: nil, kind: EntryKind.note, name: "Later", hosts: [],
                                         fields: [.init(kind: FieldKind.note, value: "x")]))
        keys = try s.knownKeys()
        XCTAssertTrue(keys.keys.contains { keys.isBehind($0) })
        XCTAssertEqual(try s.sync(with: backup), .updatedOther)
        XCTAssertEqual(try s.sync(with: backup), .inSync)

        let (file, rk) = try s.exportYkv(withRecoveryKey: true)
        XCTAssertNotNil(rk)
        XCTAssertGreaterThan(try s.importYkv(file, passphrase: "correct horse battery staple", recoveryKey: rk), 0)
        let csv = String(decoding: try s.exportPlain(.csv), as: UTF8.self)
        XCTAssertTrue(csv.hasPrefix("name,url,username,password"))
        let r = try s.importPlain(Data("name,url,username,password\nShop,https://shop.example,me,pw\n".utf8))
        XCTAssertEqual(r.imported, 1)
        try s.delete(id)
    }
}
