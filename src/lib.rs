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

trait Facade {
  fn add(&mut self)->u32;
  }

struct RoutingNode<'a> {
facade: &'a mut (Facade + 'a),
}

impl<'a> RoutingNode<'a> {
  fn new(my_facade: &'a mut Facade) -> RoutingNode<'a> {
    RoutingNode { facade: my_facade }
  }

  fn get_foo(&'a mut self) -> &'a mut Facade {
    self.facade
  }
  fn add(mut self)->u32 {
     self.facade.add()

  }
}




#[test]
fn facade_implementation() {

  struct MyFacade;
  
  impl Facade for MyFacade {
    fn add(&mut self)->u32 {
      999u32
      }
    } 
  let mut my_facade = MyFacade;
  let mut my_routing = RoutingNode::new(& mut my_facade as & mut Facade);
  assert_eq!(999, my_routing.get_foo().add()); 
}
