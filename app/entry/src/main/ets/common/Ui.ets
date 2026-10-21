/**
 * Layout shared by every screen: one gutter, one card radius, one height per row kind,
 * and the row shapes themselves so the same control looks the same everywhere.
 *
 * Global builders are plain functions: they take values and callbacks, they hold no
 * state, and they cannot read `this`. Screens pass what they know; the component that
 * owns the state re-renders them.
 */

export const PAGE_GUTTER: number = 16;
export const CARD_RADIUS: number = 16;
export const CONTENT_MAX_WIDTH: number = 720;
/** Row with a single line of text. */
export const ROW_HEIGHT: number = 52;
/** Row with a label and up to two lines of explanation underneath. */
export const ROW_MIN_HEIGHT: number = 56;

/** Hairline between rows inside a card. */
@Builder
export function rowDivider() {
  Divider()
    .strokeWidth(0.5)
    .color($r('sys.color.comp_divider'))
}

/** Small heading above a group of rows. */
@Builder
export function groupTitle(title: string) {
  Text(title)
    .fontSize(13)
    .fontWeight(FontWeight.Medium)
    .fontColor($r('sys.color.font_secondary'))
    .width('100%')
    .padding({ left: 4, bottom: 8 })
}

/** A row that opens another screen: label, current value, chevron. */
@Builder
export function navRow(label: string, value: string, highlight: boolean, onTap: () => void) {
  Row() {
    Text(label)
      .fontSize(15)
      .fontColor($r('sys.color.font_primary'))
      .layoutWeight(1)
    if (value.length > 0) {
      Text(value)
        .fontSize(13)
        .fontColor(highlight ? $r('sys.color.brand') : $r('sys.color.font_tertiary'))
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .constraintSize({ maxWidth: '60%' })
        .margin({ left: 8 })
    }
    SymbolGlyph($r('sys.symbol.chevron_right'))
      .fontSize(16)
      .fontColor([$r('sys.color.font_tertiary')])
      .margin({ left: 4 })
  }
  .width('100%')
  .height(ROW_HEIGHT)
  .alignItems(VerticalAlign.Center)
  .onClick(onTap)
}

/** A row with a switch: label, optional explanation, and the switch on the right. */
@Builder
export function toggleRow(label: string, detail: string, isOn: boolean, enabled: boolean,
  onChange: (value: boolean) => void) {
  Row() {
    Column({ space: 2 }) {
      Text(label)
        .fontSize(15)
        .fontColor($r('sys.color.font_primary'))
      if (detail.length > 0) {
        Text(detail)
          .fontSize(12)
          .fontColor($r('sys.color.font_secondary'))
          .maxLines(2)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }
    }
    .alignItems(HorizontalAlign.Start)
    .layoutWeight(1)

    Toggle({ type: ToggleType.Switch, isOn: isOn })
      .selectedColor($r('sys.color.brand'))
      .enabled(enabled)
      .onChange((value: boolean) => {
        onChange(value);
      })
  }
  .width('100%')
  .constraintSize({ minHeight: ROW_MIN_HEIGHT })
  .padding({ top: 8, bottom: 8 })
  .alignItems(VerticalAlign.Center)
  .opacity(enabled ? 1 : 0.5)
}

/** One line of the connection details sheet: label left, value right, small type. */
@Builder
export function detailRow(label: string, value: string, highlight: ResourceColor) {
  Row({ space: 12 }) {
    Text(label)
      .fontSize(14)
      .fontColor($r('sys.color.font_secondary'))
    Text(value)
      .fontSize(14)
      .fontColor(highlight)
      .layoutWeight(1)
      .textAlign(TextAlign.End)
      .maxLines(2)
      .textOverflow({ overflow: TextOverflow.Ellipsis })
  }
  .width('100%')
  .constraintSize({ minHeight: 38 })
  .alignItems(VerticalAlign.Center)
}

/** Segmented control for two or three mutually exclusive choices. */
@Builder
export function segmented(options: string[], labels: string[], active: string,
  onPick: (value: string) => void) {
  Row({ space: 4 }) {
    ForEach(options, (option: string, index: number) => {
      Button(labels[index])
        .type(ButtonType.Normal)
        .layoutWeight(1)
        .height(34)
        .borderRadius(8)
        .fontSize(11)
        .padding({ left: 0, right: 0 })
        .backgroundColor(active === option ? $r('sys.color.brand') : Color.Transparent)
        .fontColor(active === option ? Color.White : $r('sys.color.font_secondary'))
        .onClick(() => {
          onPick(option);
        })
    }, (option: string) => option)
  }
  .width('100%')
  .padding(3)
  .borderRadius(10)
  .backgroundColor($r('sys.color.comp_background_secondary'))
}

/** Read-only fact in an info card: label left, value right. */
@Builder
export function factRow(label: string, value: string) {
  Row() {
    Text(label)
      .fontSize(15)
      .fontColor($r('sys.color.font_primary'))
      .layoutWeight(1)
    Text(value)
      .fontSize(14)
      .fontColor($r('sys.color.font_secondary'))
      .textAlign(TextAlign.End)
      .constraintSize({ maxWidth: '60%' })
  }
  .width('100%')
  .height(44)
  .alignItems(VerticalAlign.Center)
}

/** Filter chip: filled when it is the active filter, a card otherwise. */
@Builder
export function chip(label: string, active: boolean, onTap: () => void) {
  Text(label)
    .fontSize(12)
    .fontWeight(active ? FontWeight.Medium : FontWeight.Normal)
    .fontColor(active ? $r('sys.color.font_on_primary') : $r('sys.color.font_secondary'))
    .padding({ left: 14, right: 14, top: 7, bottom: 7 })
    .borderRadius(16)
    .backgroundColor(active ? $r('sys.color.brand') : $r('sys.color.comp_background_primary'))
    .onClick(onTap)
}
