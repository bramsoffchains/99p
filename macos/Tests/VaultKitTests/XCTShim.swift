// XCTest ships only with Xcode; Swift Testing ships with the Command Line
// Tools too. These keep the XCTest-style assertions on top of Swift Testing.
import Testing

func XCTAssertEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T,
                                  sourceLocation: SourceLocation = #_sourceLocation) {
    do { let x = try a(), y = try b(); #expect(x == y, sourceLocation: sourceLocation) }
    catch { Issue.record(error, sourceLocation: sourceLocation) }
}
func XCTAssertTrue(_ a: @autoclosure () throws -> Bool, sourceLocation: SourceLocation = #_sourceLocation) {
    XCTAssertEqual(try a(), true, sourceLocation: sourceLocation)
}
func XCTAssertFalse(_ a: @autoclosure () throws -> Bool, sourceLocation: SourceLocation = #_sourceLocation) {
    XCTAssertEqual(try a(), false, sourceLocation: sourceLocation)
}
func XCTAssertGreaterThan<T: Comparable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T,
                                         sourceLocation: SourceLocation = #_sourceLocation) {
    do { let x = try a(), y = try b(); #expect(x > y, sourceLocation: sourceLocation) }
    catch { Issue.record(error, sourceLocation: sourceLocation) }
}
func XCTAssertNil<T>(_ a: @autoclosure () throws -> T?, sourceLocation: SourceLocation = #_sourceLocation) {
    do { let x = try a(); #expect(x == nil, sourceLocation: sourceLocation) }
    catch { Issue.record(error, sourceLocation: sourceLocation) }
}
func XCTAssertNotNil<T>(_ a: @autoclosure () throws -> T?, sourceLocation: SourceLocation = #_sourceLocation) {
    do { let x = try a(); #expect(x != nil, sourceLocation: sourceLocation) }
    catch { Issue.record(error, sourceLocation: sourceLocation) }
}
func XCTAssertThrowsError<T>(_ a: @autoclosure () throws -> T, sourceLocation: SourceLocation = #_sourceLocation,
                             _ handler: (any Error) -> Void = { _ in }) {
    do { _ = try a(); Issue.record("expected an error", sourceLocation: sourceLocation) }
    catch { handler(error) }
}
