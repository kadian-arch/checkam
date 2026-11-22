// the one call the sign-in screen uses; the package ships no type declarations of its own
declare module "qrcode" {
  export function toDataURL(text: string, options?: { margin?: number; width?: number }): Promise<string>;
}
