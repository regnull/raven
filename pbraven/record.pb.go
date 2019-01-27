// Code generated by protoc-gen-go. DO NOT EDIT.
// source: record.proto

package pbraven

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Record struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Destination          string   `protobuf:"bytes,2,opt,name=destination,proto3" json:"destination,omitempty"`
	Recepient            string   `protobuf:"bytes,3,opt,name=recepient,proto3" json:"recepient,omitempty"`
	Intermediary         string   `protobuf:"bytes,4,opt,name=intermediary,proto3" json:"intermediary,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Record) Reset()         { *m = Record{} }
func (m *Record) String() string { return proto.CompactTextString(m) }
func (*Record) ProtoMessage()    {}
func (*Record) Descriptor() ([]byte, []int) {
	return fileDescriptor_bf94fd919e302a1d, []int{0}
}

func (m *Record) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Record.Unmarshal(m, b)
}
func (m *Record) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Record.Marshal(b, m, deterministic)
}
func (m *Record) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Record.Merge(m, src)
}
func (m *Record) XXX_Size() int {
	return xxx_messageInfo_Record.Size(m)
}
func (m *Record) XXX_DiscardUnknown() {
	xxx_messageInfo_Record.DiscardUnknown(m)
}

var xxx_messageInfo_Record proto.InternalMessageInfo

func (m *Record) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Record) GetDestination() string {
	if m != nil {
		return m.Destination
	}
	return ""
}

func (m *Record) GetRecepient() string {
	if m != nil {
		return m.Recepient
	}
	return ""
}

func (m *Record) GetIntermediary() string {
	if m != nil {
		return m.Intermediary
	}
	return ""
}

func init() {
	proto.RegisterType((*Record)(nil), "pbraven.Record")
}

func init() { proto.RegisterFile("record.proto", fileDescriptor_bf94fd919e302a1d) }

var fileDescriptor_bf94fd919e302a1d = []byte{
	// 139 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x29, 0x4a, 0x4d, 0xce,
	0x2f, 0x4a, 0xd1, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x2f, 0x48, 0x2a, 0x4a, 0x2c, 0x4b,
	0xcd, 0x53, 0x6a, 0x60, 0xe4, 0x62, 0x0b, 0x02, 0xcb, 0x08, 0x09, 0x71, 0xb1, 0xe4, 0x25, 0xe6,
	0xa6, 0x4a, 0x30, 0x2a, 0x30, 0x6a, 0x70, 0x06, 0x81, 0xd9, 0x42, 0x0a, 0x5c, 0xdc, 0x29, 0xa9,
	0xc5, 0x25, 0x99, 0x79, 0x89, 0x25, 0x99, 0xf9, 0x79, 0x12, 0x4c, 0x60, 0x29, 0x64, 0x21, 0x21,
	0x19, 0x2e, 0xce, 0xa2, 0xd4, 0xe4, 0xd4, 0x82, 0xcc, 0xd4, 0xbc, 0x12, 0x09, 0x66, 0xb0, 0x3c,
	0x42, 0x40, 0x48, 0x89, 0x8b, 0x27, 0x33, 0xaf, 0x24, 0xb5, 0x28, 0x37, 0x35, 0x25, 0x33, 0xb1,
	0xa8, 0x52, 0x82, 0x05, 0xac, 0x00, 0x45, 0x2c, 0x89, 0x0d, 0xec, 0x24, 0x63, 0x40, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x46, 0xbf, 0x2c, 0xf1, 0xa2, 0x00, 0x00, 0x00,
}
