import SwiftUI

/// The macOS 27 SDK turns `@State` into a macro whose plugin ships only with
/// Xcode. Using the property-wrapper type through an alias lets the app build
/// with the Command Line Tools alone.
typealias Local<Value> = SwiftUI.State<Value>
