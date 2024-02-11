#include "Color.hpp"
#include "Constant.hpp"
#include "FieldValueWithWeight.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"
#include "MapSetFieldValues.hpp"
#include "MediaType.hpp"
#include "MultiFieldValues.hpp"
#include "SingleFieldValue.hpp"
#include "ValueAndMapFieldValues.hpp"

namespace {

Result<double, int> parse_weight(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos) {
	Result<int, int> parse_result;
	std::size_t end;
	std::string key, value;
	double weight;
	bool succeed;

	if (!end_pos) {
		return Result<double, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.length() < start_pos) {
		return Result<double, int>::err(ERR);
	}
	parse_result = HttpMessageParser::parse_parameter(field_value,
													  start_pos, &end,
													  &key, &value,
													  HttpMessageParser::skip_token,
													  HttpMessageParser::skip_token);

	if (parse_result.is_err()) {
		return Result<double, int>::err(ERR);
	}

	if (key != std::string(WEIGHT_KEY)) {
		return Result<double, int>::err(ERR);
	}
	weight = HttpMessageParser::to_floating_num(value, 3, &succeed);

	if (!succeed || weight < 0.0 || 1.0 < weight) {
		return Result<double, int>::err(ERR);
	}
	*end_pos = end;
	return Result<double, int>::ok(weight);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

FieldValueWithWeight::FieldValueWithWeight()
	: field_value_(NULL),
      weight_(WEIGHT_INIT) {}

FieldValueWithWeight::FieldValueWithWeight(FieldValueBase *field_value,
										   double weight)
	: field_value_(field_value),
      weight_(weight) {
}

FieldValueWithWeight::FieldValueWithWeight(const FieldValueWithWeight &other)
	: field_value_(NULL) {
	*this = other;
}

FieldValueWithWeight &FieldValueWithWeight::operator=(const FieldValueWithWeight &rhs) {
	if (this == &rhs) {
		return *this;
	}

	FieldValueBase *copy_ptr = NULL;
	if (dynamic_cast<MapFieldValues *>(rhs.field_value_)) {
		copy_ptr = new MapFieldValues(*(static_cast<MapFieldValues *>(rhs.field_value_)));
	} else if (dynamic_cast<MapSetFieldValues *>(rhs.field_value_)) {
		copy_ptr = new MapSetFieldValues(*(static_cast<MapSetFieldValues *>(rhs.field_value_)));
	} else if (dynamic_cast<MediaType *>(rhs.field_value_)) {
		copy_ptr = new MediaType(*(static_cast<MediaType *>(rhs.field_value_)));
	} else if (dynamic_cast<MultiFieldValues *>(rhs.field_value_)) {
		copy_ptr = new MultiFieldValues(*(static_cast<MultiFieldValues *>(rhs.field_value_)));
	} else if (dynamic_cast<SingleFieldValue *>(rhs.field_value_)) {
		copy_ptr = new SingleFieldValue(*(static_cast<SingleFieldValue *>(rhs.field_value_)));
	} else if (dynamic_cast<ValueAndMapFieldValues *>(rhs.field_value_)) {
		copy_ptr = new ValueAndMapFieldValues(*(static_cast<ValueAndMapFieldValues *>(rhs.field_value_)));
	}

	delete this->field_value_;
	this->field_value_ = copy_ptr;

	this->weight_ = rhs.weight_;
	return *this;
}

bool FieldValueWithWeight::operator<(const FieldValueWithWeight &rhs) const {
	return this->weight_ < rhs.weight_;
}

FieldValueWithWeight::~FieldValueWithWeight() {
	delete this->field_value_;
	this->field_value_ = NULL;
}

FieldValueBase *FieldValueWithWeight::get_field_value() const {
	return this->field_value_;
}

double FieldValueWithWeight::get_weight() const {
	return this->weight_;
}

////////////////////////////////////////////////////////////////////////////////

FieldValueWithWeightSet::FieldValueWithWeightSet(const std::set<FieldValueWithWeight> &field_values)
	: field_values_(field_values) {}

FieldValueWithWeightSet::FieldValueWithWeightSet(const FieldValueWithWeightSet &other) {
	*this = other;
}

FieldValueWithWeightSet &FieldValueWithWeightSet::operator=(const FieldValueWithWeightSet &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->field_values_ = rhs.field_values_;
	return *this;
}

FieldValueWithWeightSet::~FieldValueWithWeightSet() {}

std::set<FieldValueWithWeight> FieldValueWithWeightSet::get_field_values() const {
	return this->field_values_;
}

////////////////////////////////////////////////////////////////////////////////

/*
 weight = OWS ";" OWS "q=" qvalue
 qvalue = ( "0" [ "." 0*3DIGIT ] )
        / ( "1" [ "." 0*3("0") ] )
 */
Result<double, int> FieldValueWithWeight::parse_valid_weight(const std::string &field_value,
															 std::size_t start_pos,
															 std::size_t *end_pos) {
	std::size_t pos, end;
	double weight;
	Result<double, int> parse_result;

	if (!end_pos) {
		return Result<double, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.length() < start_pos) {
		return Result<double, int>::err(ERR);
	}

	pos = start_pos;
	if (field_value[pos] == ';') {
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);

		parse_result = parse_weight(field_value, pos, &end);
		if (parse_result.is_err()) {
			return Result<double, int>::err(ERR);
		}
		weight = parse_result.get_ok_value();
		pos = end;
	} else {
		weight = WEIGHT_INIT;
	}
	*end_pos = pos;
	return Result<double, int>::ok(weight);
}
