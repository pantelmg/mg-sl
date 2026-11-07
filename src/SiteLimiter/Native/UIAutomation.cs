using System.Runtime.InteropServices;

namespace SiteLimiter.Native;

// Hand-written UI Automation COM declarations (no WindowsDesktop/NuGet dependency).
// Vtable order follows UIAutomationClient.h; unused slots are placeholders and are never called.

[ComImport, Guid("ff48dba4-60ef-4201-aa87-54103eef594e")]
internal class CUIAutomation { }

[ComImport, Guid("30cbe57d-d9d0-452a-ab13-7ac5ac4825ee"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IUIAutomation
{
    void _CompareElements();
    void _CompareRuntimeIds();
    void _GetRootElement();
    [PreserveSig] int ElementFromHandle(IntPtr hwnd, [MarshalAs(UnmanagedType.Interface)] out IUIAutomationElement? element);
    void _ElementFromPoint();
    void _GetFocusedElement();
    void _GetRootElementBuildCache();
    void _ElementFromHandleBuildCache();
    void _ElementFromPointBuildCache();
    void _GetFocusedElementBuildCache();
    void _CreateTreeWalker();
    void _get_ControlViewWalker();
    void _get_ContentViewWalker();
    void _get_RawViewWalker();
    void _get_RawViewCondition();
    void _get_ControlViewCondition();
    void _get_ContentViewCondition();
    void _CreateCacheRequest();
    void _CreateTrueCondition();
    void _CreateFalseCondition();
    [PreserveSig] int CreatePropertyCondition(int propertyId, [MarshalAs(UnmanagedType.Struct)] object value, out IntPtr condition);
}

[ComImport, Guid("d22108aa-8ac5-49a5-837b-37bbb3d7591e"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
internal interface IUIAutomationElement
{
    void _SetFocus();
    void _GetRuntimeId();
    [PreserveSig] int FindFirst(int scope, IntPtr condition, [MarshalAs(UnmanagedType.Interface)] out IUIAutomationElement? found);
    void _FindAll();
    void _FindFirstBuildCache();
    void _FindAllBuildCache();
    void _BuildUpdatedCache();
    [PreserveSig] int GetCurrentPropertyValue(int propertyId, [MarshalAs(UnmanagedType.Struct)] out object? value);
}

internal static class Uia
{
    public const int TreeScope_Descendants = 4;
    public const int ControlTypeProperty = 30003, NameProperty = 30005, HasKeyboardFocusProperty = 30008,
                     AutomationIdProperty = 30011, ClassNameProperty = 30012, ValueValueProperty = 30045;
    public const int EditControlType = 50004;
}
