/// Dates and money for the parent screens in uz/ru/ko/en, without a locale
/// data download (intl's date symbols are not initialised in this app).
library;

const _weekdays = {
  'uz': [
    'Dushanba',
    'Seshanba',
    'Chorshanba',
    'Payshanba',
    'Juma',
    'Shanba',
    'Yakshanba',
  ],
  'ru': [
    'понедельник',
    'вторник',
    'среда',
    'четверг',
    'пятница',
    'суббота',
    'воскресенье',
  ],
  'ko': ['월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일'],
  'en': [
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday',
    'Sunday',
  ],
};

const _monthsShort = {
  'uz': [
    'yan',
    'fev',
    'mar',
    'apr',
    'may',
    'iyun',
    'iyul',
    'avg',
    'sen',
    'okt',
    'noy',
    'dek',
  ],
  'ru': [
    'янв',
    'фев',
    'мар',
    'апр',
    'мая',
    'июн',
    'июл',
    'авг',
    'сен',
    'окт',
    'ноя',
    'дек',
  ],
  'en': [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ],
};

const _monthsFull = {
  'uz': [
    'Yanvar',
    'Fevral',
    'Mart',
    'Aprel',
    'May',
    'Iyun',
    'Iyul',
    'Avgust',
    'Sentabr',
    'Oktabr',
    'Noyabr',
    'Dekabr',
  ],
  'ru': [
    'Январь',
    'Февраль',
    'Март',
    'Апрель',
    'Май',
    'Июнь',
    'Июль',
    'Август',
    'Сентябрь',
    'Октябрь',
    'Ноябрь',
    'Декабрь',
  ],
  'en': [
    'January',
    'February',
    'March',
    'April',
    'May',
    'June',
    'July',
    'August',
    'September',
    'October',
    'November',
    'December',
  ],
};

String _lang(String lang) => _weekdays.containsKey(lang) ? lang : 'en';

/// "24-okt", "24 окт", "10월 24일", "24 Oct".
String shortDate(String lang, DateTime d) => switch (_lang(lang)) {
  'uz' => '${d.day}-${_monthsShort['uz']![d.month - 1]}',
  'ko' => '${d.month}월 ${d.day}일',
  final l => '${d.day} ${_monthsShort[l]![d.month - 1]}',
};

/// "Payshanba, 24-okt" (the Today card's eyebrow, upper-cased by the caller).
String weekdayDate(String lang, DateTime d) {
  final l = _lang(lang);
  final day = _weekdays[l]![d.weekday - 1];
  return l == 'ko' ? '${shortDate(l, d)} $day' : '$day, ${shortDate(l, d)}';
}

/// "Noyabr", "Ноябрь", "11월", "November".
String monthName(String lang, DateTime d) => switch (_lang(lang)) {
  'ko' => '${d.month}월',
  final l => _monthsFull[l]![d.month - 1],
};

/// "450 000" from "450000.00" (no decimals for whole sums).
String groupedAmount(String raw) {
  final value = double.tryParse(raw) ?? 0;
  final whole = value.truncate();
  final digits = whole.abs().toString();
  final out = StringBuffer(whole < 0 ? '-' : '');
  for (var i = 0; i < digits.length; i++) {
    if (i > 0 && (digits.length - i) % 3 == 0) out.write(' ');
    out.write(digits[i]);
  }
  final cents = ((value - whole).abs() * 100).round();
  if (cents > 0) out.write(',${cents.toString().padLeft(2, '0')}');
  return out.toString();
}
