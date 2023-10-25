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
													  &key, &value);
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
	: _field_value(NULL),
	  _weight(WEIGHT_INIT) {}

FieldValueWithWeight::FieldValueWithWeight(FieldValueBase *field_value,
										   double weight)
	: _field_value(field_value),
	  _weight(weight) {
}

FieldValueWithWeight::FieldValueWithWeight(const FieldValueWithWeight &other)
	: _field_value(NULL) {
	*this = other;
}

FieldValueWithWeight &FieldValueWithWeight::operator=(const FieldValueWithWeight &rhs) {
	if (this == &rhs) {
		return *this;
	}

	FieldValueBase *copy_ptr = NULL;
	if (dynamic_cast<MapFieldValues *>(rhs._field_value)) {
		copy_ptr = new MapFieldValues(*(static_cast<MapFieldValues *>(rhs._field_value)));
	} else if (dynamic_cast<MapSetFieldValues *>(rhs._field_value)) {
		copy_ptr = new MapSetFieldValues(*(static_cast<MapSetFieldValues *>(rhs._field_value)));
	} else if (dynamic_cast<MediaType *>(rhs._field_value)) {
		copy_ptr = new MediaType(*(static_cast<MediaType *>(rhs._field_value)));
	} else if (dynamic_cast<MultiFieldValues *>(rhs._field_value)) {
		copy_ptr = new MultiFieldValues(*(static_cast<MultiFieldValues *>(rhs._field_value)));
	} else if (dynamic_cast<SingleFieldValue *>(rhs._field_value)) {
		copy_ptr = new SingleFieldValue(*(static_cast<SingleFieldValue *>(rhs._field_value)));
	} else if (dynamic_cast<ValueAndMapFieldValues *>(rhs._field_value)) {
		copy_ptr = new ValueAndMapFieldValues(*(static_cast<ValueAndMapFieldValues *>(rhs._field_value)));
	}

	delete this->_field_value;
	this->_field_value = copy_ptr;

	this->_weight = rhs._weight;
	return *this;
}

bool FieldValueWithWeight::operator<(const FieldValueWithWeight &rhs) const {
	return this->_weight < rhs._weight;
}

FieldValueWithWeight::~FieldValueWithWeight() {
	delete this->_field_value;
	this->_field_value = NULL;
}

FieldValueBase *FieldValueWithWeight::get_field_value() const {
	return this->_field_value;
}

double FieldValueWithWeight::get_weight() const {
	return this->_weight;
}

////////////////////////////////////////////////////////////////////////////////

FieldValueWithWeightSet::FieldValueWithWeightSet(const std::set<FieldValueWithWeight> &field_values)
	: _field_values(field_values) {}

FieldValueWithWeightSet::FieldValueWithWeightSet(const FieldValueWithWeightSet &other) {
	*this = other;
}

FieldValueWithWeightSet &FieldValueWithWeightSet::operator=(const FieldValueWithWeightSet &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_field_values = rhs._field_values;
	return *this;
}

FieldValueWithWeightSet::~FieldValueWithWeightSet() {}

std::set<FieldValueWithWeight> FieldValueWithWeightSet::get_field_values() const {
	return this->_field_values;
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
