/*  Copyright 2014 MaidSafe.net limited
    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").
    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses
    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.
    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe
    Software.                                                                 */


mod routing_table;
use std::marker::MarkerTrait;

trait Facade : MarkerTrait {
  fn add(&mut self);
  }

struct RoutingNode<'a> {
facade: &'a (Facade + 'a),
}

impl<'a> RoutingNode<'a> {
  fn new(my_facade: &'a Facade) -> RoutingNode<'a> {
    RoutingNode { facade: my_facade }
  }

  fn get_foo(&'a self) -> &'a Facade {
    self.facade
  }
}




#[test]
fn facade_implementation() {
  struct ImmutableData {
    name: String,
    content: String,
    tag: u8
    }

  struct MutableData {
    name: String,
    content: String,
    tag: u8
    }

  enum DataTypes {
    ImmutableData,
    MutableData
    }

  struct MyFacade {
    data_types: DataTypes,
    persona: u8,
    }
  
  impl Facade for MyFacade {
    fn add(&mut self) {
      self.persona += 1
      }
    } 

}
