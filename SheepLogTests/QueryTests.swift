import XCTest
@testable import SheepLog

final class QueryTests: XCTestCase {
    private func leaf(_ text: String) -> (QueryNode) -> Bool {
        { node in
            switch node {
            case .text(let t): return QueryMatch.contains(text, t)
            case .regex(let r): return QueryMatch.regexMatches(r, text)
            case .field(let k, let op, let v):
                if k == "len" { return QueryMatch.compare(text.count, op, Int(v) ?? 0) }
                return false
            default: return false
            }
        }
    }

    func testImplicitAnd() throws {
        let q = try Query.parse("login failed")
        XCTAssertTrue(q.matches(leaf("User login failed from 10.1.0.1")))
        XCTAssertFalse(q.matches(leaf("User login ok")))
    }

    func testOrNotNor() throws {
        XCTAssertTrue(try Query.parse("alpha OR beta").matches(leaf("only beta here")))
        XCTAssertFalse(try Query.parse("NOT beta").matches(leaf("only beta here")))
        XCTAssertFalse(try Query.parse("-beta").matches(leaf("only beta here")))
        XCTAssertTrue(try Query.parse("alpha NOR beta").matches(leaf("gamma")))
        XCTAssertFalse(try Query.parse("alpha NOR beta").matches(leaf("alpha")))
    }

    func testPrecedenceAndParens() throws {
        // a OR b c  ==  a OR (b AND c)
        let q = try Query.parse("a OR b c")
        XCTAssertTrue(q.matches(leaf("a")))
        XCTAssertFalse(q.matches(leaf("b")))
        XCTAssertTrue(q.matches(leaf("b c")))
        let p = try Query.parse("(a OR b) c")
        XCTAssertFalse(p.matches(leaf("a")))
        XCTAssertTrue(p.matches(leaf("a c")))
    }

    func testPhraseAndField() throws {
        XCTAssertTrue(try Query.parse("\"login failed\"").matches(leaf("x login failed y")))
        XCTAssertFalse(try Query.parse("\"login failed\"").matches(leaf("login has failed")))
        XCTAssertTrue(try Query.parse("len:<=5").matches(leaf("abc")))
        XCTAssertFalse(try Query.parse("len>=5").matches(leaf("abc")))
        XCTAssertEqual(try Query.parse("sev:<=warn").root, .field(key: "sev", op: .le, value: "warn"))
        XCTAssertEqual(try Query.parse("f:srcip=10.1.2.3").root, .field(key: "f", op: .eq, value: "srcip=10.1.2.3"))
    }

    func testRegex() throws {
        XCTAssertTrue(try Query.parse("/fail(ed|ure)/").matches(leaf("auth failure")))
        XCTAssertTrue(try Query.parse("fail.re", regexWords: true).matches(leaf("auth failure")))
        XCTAssertThrowsError(try Query.parse("/(/"))
    }

    func testErrors() throws {
        XCTAssertThrowsError(try Query.parse("\"open"))
        XCTAssertThrowsError(try Query.parse("(a"))
        XCTAssertThrowsError(try Query.parse("a AND"))
        XCTAssertTrue(try Query.parse("   ").isEmpty)
    }
}
