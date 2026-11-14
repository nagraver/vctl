import AppKit
let source = CommandLine.arguments[1]
let target = CommandLine.arguments[2]
guard let image = NSImage(contentsOfFile: source) else { fatalError("Cannot load SVG") }
let bitmap = NSBitmapImageRep(bitmapDataPlanes:nil,pixelsWide:1024,pixelsHigh:1024,bitsPerSample:8,samplesPerPixel:4,hasAlpha:true,isPlanar:false,colorSpaceName:.deviceRGB,bytesPerRow:0,bitsPerPixel:0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep:bitmap)
// Keep the visible tile at roughly 824 px on the 1024 px macOS icon canvas.
image.draw(in:NSRect(x:64,y:64,width:896,height:896))
NSGraphicsContext.restoreGraphicsState()
try bitmap.representation(using:.png,properties:[:])!.write(to:URL(fileURLWithPath:target))
